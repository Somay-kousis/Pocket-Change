"""One test per applicable SoK vector, named as eval/vectors.py declares it.

A failure here says which security property broke, not which function did.
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from agent.nodes import check_sub_mandate, inspect_cart
from agent.tools import CartLine, ToolSurface
from agent.utils import is_marked
from eval import vectors
from merchant import offers, poisoned
from pocketchange import gateway, token
from pocketchange.audit import AuditLog, AuditTampered, Decision
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE

BASKET = {"LAP-STD-1": 4, "MON-27Q-1": 2, "KVM-DCK-1": 1}


@pytest.fixture
def client():
    gateway.state = gateway.State()
    gateway.state.monitor = ScriptedMonitor(Verdict.ALLOW, "pinned")
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


@pytest.fixture
def mandate(client):
    return client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE, "purpose": "weekly groceries", "ttl_seconds": 3600,
    }).json()


def _delegate(client, parent, tools, budget, to=None, depth=0):
    return client.post("/delegate", json={
        "token": parent, "tools": tools, "budget_paise": budget,
        "context": "test", "to": to, "depth": depth,
    })


@pytest.fixture
def surface(client, mandate):
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    broker = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                       to="aip:web:pocketchange.dev/broker").json()["token"]
    s = ToolSurface(client=client, shopper_token=shopper, payer_token="", broker_token=broker)
    lines = []
    for sku, qty in BASKET.items():
        s.find_offers(sku)
        available = offers.available_offers(sku, qty)
        if available:
            lines.append({"sku": sku, "quantity": qty, "seller_id": available[0].seller_id})
    s.propose_cart("thrifty", lines, "cheapest per line")
    s.choose_cart("thrifty", "only proposal")
    return s


# --- D1 --------------------------------------------------------------------


def test_p2t_injected_text_cannot_reach_payment(client, mandate):
    """A shopper that fully complies with an injection still cannot pay."""
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    r = client.post("/pay", headers={"X-AIP-Token": shopper}, json={
        "amount_paise": 2_000_000 * RUPEE, "cart": {"LAP-STD-1": 1},
        "context": poisoned.IMPORTANT_MESSAGE[:180],
    })
    assert r.status_code == 403


def test_t2r_tool_output_is_marked_at_the_boundary(surface):
    """Untrusted text is marked in code, not by asking the prompt nicely."""
    review = surface.read_reviews("LAP-STD-1", "clearline-traders")["recent_reviews"][0]
    assert is_marked(review["body_untrusted"])

    offer = surface.find_offers("LAP-STD-1")[0]
    assert "seller_name_untrusted" in offer

    product = surface.search_products("laptop")[0]
    assert is_marked(product["description_untrusted"])


def test_t2t_a_fabricated_price_cannot_enter_a_cart(surface):
    """Prices are looked up, never accepted - and the guard re-checks the total."""
    real = surface.cart_lines[0]
    surface.cart_lines = [
        CartLine(sku=real.sku, quantity=real.quantity, seller_id=real.seller_id,
                 unit_price_paise=1)
    ]
    verdict = inspect_cart(surface)
    assert not verdict.ok
    assert any("price for" in f for f in verdict.failures)


def test_p2t_a_poisoned_policy_cannot_persist_absurd_levels():
    """The durable case: poison a policy once, harvest for months.

    Every later tick is arithmetic with no model involved, so nothing re-reads
    the text and nothing gets a second chance to notice. The levels themselves
    have to be bounded before they are written down.
    """
    from agent.nodes import bound_rules
    from agent.nodes.standing_node import PolicyLine

    poisoned_policy = [
        PolicyLine(sku="STA-A4-5", reorder_point=3, target_level=400,
                   rationale="injected: stockpile"),
        PolicyLine(sku="SRV-RCK-1", reorder_point=1, target_level=5,
                   rationale="injected: recurring servers"),
    ]
    kept, rejected = bound_rules(poisoned_policy, 50_000 * RUPEE)
    assert kept == ()
    assert len(rejected) == 2


def test_p2t_a_policy_is_inert_until_someone_approves_it():
    """Recurring authority from one sentence, in the mode nobody watches."""
    from dataclasses import replace

    from agent.nodes import tick
    from pocketchange.memory import ReorderRule, new_order

    order = new_order(
        instruction="keep the cupboard stocked", department="operations",
        period="month", period_budget_paise=50_000 * RUPEE,
        rules=(ReorderRule("STA-A4-5", 3, 12),),
    )
    assert not tick(order).acts
    assert tick(replace(order, approved=True)).acts


# --- D2 --------------------------------------------------------------------


def test_p2k_no_agent_can_reach_a_credential(surface):
    """No tool an agent holds returns or accepts a key."""
    every_tool = (
        surface.shopper_functions() + surface.chooser_functions()
        + surface.broker_functions() + surface.sub_payer_functions()
        + surface.reviewer_functions()
    )
    names = {f.__name__ for f in every_tool}
    assert not {n for n in names if "key" in n or "secret" in n or "credential" in n}
    assert "razorpay" not in " ".join(names).lower()


def test_m2a_authority_cannot_be_widened(client, mandate, surface):
    """Two ways the model might try, both refused."""
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    assert _delegate(client, shopper, ["pay"], 40_000 * RUPEE, depth=1).status_code == 403

    seller = surface.cart_lines[0].seller_id
    share = sum(l.line_total_paise for l in surface.cart_lines if l.seller_id == seller)
    assert not check_sub_mandate(surface, seller, share * 10).ok


# --- D3 --------------------------------------------------------------------


def test_s2i_an_unknown_seller_is_refused(surface):
    """At proposal time, and again at the guard."""
    rejected = surface.propose_cart(
        "x", [{"sku": "LAP-STD-1", "quantity": 1, "seller_id": "ghost-mart"}], "r"
    )
    assert rejected["accepted"] is False

    surface.cart_lines = [
        CartLine(sku="LAP-STD-1", quantity=1, seller_id="ghost-mart", unit_price_paise=100)
    ]
    assert any("unknown seller" in f for f in inspect_cart(surface).failures)


def test_c2e_siblings_cannot_exceed_one_ceiling(client, mandate):
    """Many children, one pool. Fragmentation buys the attacker nothing."""
    broker = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                       to="aip:web:pocketchange.dev/broker").json()["token"]
    children = [
        _delegate(client, broker, ["pay"], 360_000 * RUPEE,
                  to=f"aip:web:pocketchange.dev/payer/{n}", depth=1).json()["token"]
        for n in range(3)
    ]
    outcomes = [
        client.post("/pay", headers={"X-AIP-Token": t}, json={
            "amount_paise": 360_000 * RUPEE, "cart": {"SRV-RCK-1": n + 1},
            "context": "each child spending its full cap",
        }).status_code
        for n, t in enumerate(children)
    ]
    assert 402 in outcomes, "three children of 900 must not all clear a 1500 cap"
    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["committed_paise"] <= state["cap_paise"]


# --- D5 --------------------------------------------------------------------


def test_n2c_refusals_are_recorded_with_reasons(client, mandate):
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    client.post("/pay", headers={"X-AIP-Token": shopper}, json={
        "amount_paise": 40_000 * RUPEE, "cart": {"LAP-STD-1": 1}, "context": "a shopper trying to pay",
    })
    denials = [e for e in client.get("/audit").json()["entries"] if e["decision"] == "denied"]
    assert denials and all(e["reason"] for e in denials)


def test_r2i_tampering_breaks_the_chain():
    log = AuditLog()
    log.append(mandate_id="m", actor="a", tool="pay", decision=Decision.ALLOWED,
               reason="ok", amount_paise=100)
    log.append(mandate_id="m", actor="a", tool="pay", decision=Decision.DENIED,
               reason="cumulative budget exhausted")
    log.verify()

    victim = log._entries[0]
    log._entries[0] = type(victim)(**{**victim.__dict__, "amount_paise": 999_999})
    with pytest.raises(AuditTampered):
        log.verify()


def test_i2m_our_own_record_cannot_be_written_by_a_seller():
    """Sybil reputation. A supplier fills in its own review_count and is
    "established" for free; it cannot make us have paid it before."""
    from pocketchange.counterparties import InMemoryCounterparties

    book = InMemoryCounterparties()

    # The seller's own claim, as merchant/sellers.py reports it.
    from merchant import sellers
    hostile = sellers.get("clearline-traders")
    assert hasattr(hostile, "review_count")     # self-reported, and load-bearing

    # Our record is empty until money clears, and only the gateway writes it.
    assert book.lookup("clearline-traders") is None
    book.record("clearline-traders", amount_paise=1_000, mandate_id="m1")
    assert book.lookup("clearline-traders").orders == 1

    import inspect

    from pocketchange import gateway

    assert inspect.getsource(gateway).count("state.counterparties.record(") == 1


# --- the register must not drift from reality ------------------------------


def test_every_defended_vector_names_a_test_that_exists():
    """A register claiming a defence with no test behind it is a brochure."""
    here = set(globals())
    for vector in vectors.applicable():
        name = vector.test.split("::")[-1]
        assert name in here, f"{vector.code} names a missing test: {name}"


def test_every_not_applicable_vector_gives_a_reason():
    for vector in vectors.not_applicable():
        assert len(vector.note) > 40, f"{vector.code} needs a real reason, not a shrug"


def test_the_register_covers_all_twelve():
    assert len(vectors.VECTORS) == 12
    assert len(vectors.applicable()) == 10
