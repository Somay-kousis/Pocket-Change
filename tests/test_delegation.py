"""The agent minting its own mandates, one per seller.

Two guarantees of different kinds, and the tests say which is which:

  cryptographic  a sub-payer cannot exceed its seller's subtotal, cannot pay
                 another seller, and a shopper cannot mint itself a payer
  policy         a broker may grant `pay` without spending it - attenuation is
                 monotonic, so the token cannot express that and the gateway does
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from agent.tools import ToolSurface
from merchant import offers
from pocketchange import gateway, token
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE

BASKET = {"LAP-STD-1": 4, "MON-27Q-1": 2, "CHR-ERG-1": 1, "KVM-DCK-1": 1}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
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
        "context": "test delegation", "to": to, "depth": depth,
    })


@pytest.fixture
def tools(client, mandate):
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    broker = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                       to="aip:web:pocketchange.dev/broker").json()["token"]
    surface = ToolSurface(client=client, shopper_token=shopper, payer_token="",
                          broker_token=broker)
    lines = []
    for sku, qty in BASKET.items():
        available = offers.available_offers(sku, qty)
        if available:
            lines.append({"sku": sku, "quantity": qty, "seller_id": available[0].seller_id})
    surface.propose_cart("thrifty", lines, "cheapest per line")
    surface.choose_cart("thrifty", "only proposal")
    return surface


# --- cryptographic guarantees ---------------------------------------------


def test_a_shopper_cannot_mint_itself_a_payer(client, mandate):
    """Without this the sibling separation collapses in one call."""
    shopper = _delegate(client, mandate["token"], ["search", "cart"], 600_000 * RUPEE).json()["token"]
    r = _delegate(client, shopper, ["pay"], 40_000 * RUPEE, depth=1)
    assert r.status_code == 403
    assert "may not delegate" in r.json()["detail"]["denied"]


def test_sub_payer_cannot_exceed_its_cap(client, tools):
    seller = tools.cart_lines[0].seller_id
    tools.delegate_for_seller(seller, "paying this seller")
    r = client.post("/pay", headers={"X-AIP-Token": tools.sub_mandates[seller]}, json={
        "amount_paise": 560_000 * RUPEE, "cart": {"SRV-RCK-1": 3},
        "context": "a compromised sub-payer reaching for the whole mandate",
    })
    assert r.status_code == 403


def test_children_share_one_ceiling(client, tools, mandate):
    """Fragmentation: many children, still one pool."""
    for seller in {line.seller_id for line in tools.cart_lines}:
        out = tools.delegate_for_seller(seller, f"paying {seller}")
        assert out["delegated"] is True
    for seller in list(tools.sub_mandates):
        tools.checkout_seller(seller, f"settling {seller}")

    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["committed_paise"] <= state["cap_paise"]
    assert state["committed_paise"] > 0


def test_every_child_carries_the_parents_mandate_id(client, mandate):
    broker = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                       to="aip:web:pocketchange.dev/broker").json()
    child = _delegate(client, broker["token"], ["pay"], 120_000 * RUPEE, depth=1).json()
    assert child["mandate_id"] == mandate["mandate_id"]


def test_attenuation_cannot_express_grant_without_use():
    """The finding this design had to work around, asserted so it stays true.

    A broker scoped to delegate-only produces children that cannot pay; scoped to
    delegate+pay it can pay itself. There is no middle.
    """
    from datetime import datetime, timedelta, timezone

    from biscuit_auth import KeyPair

    from pocketchange import identity
    from pocketchange.policy import Grant, Operation

    principal = identity.web("pocketchange.dev", "principal", keypair=KeyPair())
    root = token.mint(principal, budget_paise=150_000, max_depth=3,
                      expires=datetime.now(timezone.utc) + timedelta(hours=1))

    def can_pay(t):
        try:
            token.verify(t, Operation("pay", 100, depth=1))
            return True
        except token.Denied:
            return False

    narrow = token.attenuate(root, to="x", grant=Grant(("delegate",), 150_000), context="c")
    narrow_child = token.attenuate(narrow, to="y", grant=Grant(("pay",), 30_000), context="c")
    assert not can_pay(narrow) and not can_pay(narrow_child)

    wide = token.attenuate(root, to="x", grant=Grant(("delegate", "pay"), 150_000), context="c")
    wide_child = token.attenuate(wide, to="y", grant=Grant(("pay",), 30_000), context="c")
    assert can_pay(wide) and can_pay(wide_child)


# --- policy guarantee ------------------------------------------------------


def test_broker_may_grant_but_not_spend(client, mandate):
    """Enforced at the gateway by identity, not by the chain. Labelled as such."""
    broker = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                       to="aip:web:pocketchange.dev/broker").json()["token"]
    r = client.post("/pay", headers={"X-AIP-Token": broker}, json={
        "amount_paise": 40_000 * RUPEE, "cart": {"LAP-STD-1": 1},
        "context": "paying directly instead of delegating",
    })
    assert r.status_code == 403
    assert "broker may delegate, not spend" in r.json()["detail"]["denied"]


def test_is_broker_reads_the_signed_block(client, mandate):
    broker_raw = _delegate(client, mandate["token"], ["delegate", "pay"], 600_000 * RUPEE,
                           to="aip:web:pocketchange.dev/broker").json()["token"]
    payer_raw = _delegate(client, mandate["token"], ["pay"], 120_000 * RUPEE,
                          to="aip:web:pocketchange.dev/payer/anand").json()["token"]
    pub = gateway.state.root_public_key
    assert token.is_broker(token.deserialize(broker_raw, pub))
    assert not token.is_broker(token.deserialize(payer_raw, pub))


# --- splitting and delegating ----------------------------------------------


def test_split_groups_by_seller_and_totals_match(tools):
    split = tools.split_by_seller()
    assert split["seller_count"] >= 2
    assert split["total_paise"] == sum(g["subtotal_paise"] for g in split["groups"])
    assert split["total_paise"] == sum(line.line_total_paise for line in tools.cart_lines)


def test_sub_mandate_is_capped_at_that_sellers_subtotal(tools):
    seller = tools.cart_lines[0].seller_id
    expected = sum(line.line_total_paise for line in tools.cart_lines
                   if line.seller_id == seller)
    assert tools.delegate_for_seller(seller, "paying this seller")["cap_paise"] == expected


def test_delegating_for_a_seller_not_in_the_cart_is_refused(tools):
    assert "error" in tools.delegate_for_seller("northgate-supply", "not in this cart")


def test_delegation_requires_a_stated_reason(tools):
    seller = tools.cart_lines[0].seller_id
    assert "error" in tools.delegate_for_seller(seller, "   ")


def test_checkout_requires_a_mandate_first(tools):
    seller = tools.cart_lines[0].seller_id
    assert "error" in tools.checkout_seller(seller, "paying without delegating")


def test_a_surface_without_a_broker_token_cannot_delegate(client):
    surface = ToolSurface(client=client, shopper_token="s", payer_token="p")
    assert "error" in surface.delegate_for_seller("vector-distribution", "no broker token")


def test_broker_holds_no_payment_tools(tools):
    names = {f.__name__ for f in tools.broker_functions()}
    assert names == {"split_by_seller", "delegate_for_seller"}
