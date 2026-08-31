"""Per-token and cumulative budget.

The mandate cap is cumulative in the ledger. Since the envelope fix, so is every
delegated budget: a sub-payer capped at a seller's subtotal can spend that
subtotal once in total, not once per cart.
"""

import threading

import pytest
from fastapi.testclient import TestClient

from pocketchange import gateway, token
from pocketchange.policy import Grant
from pocketchange.razorpay_client import PaymentError


def _narrow_offline(gw, raw, budget, to="aip:web:pocketchange.dev/payer/self"):
    parent = token.deserialize(raw, gw.state.root_public_key)
    child = token.attenuate(parent, to=to, grant=Grant(("pay",), budget),
                            context="narrowing myself for a fresh allowance")
    return token.serialize(child)


# --- the mandate's own ceiling -------------------------------------------------

@pytest.mark.agent
def test_second_payment_past_the_mandate_cap(gw):
    m = gw.mandate(budget=10_000)
    assert gw.pay(m["token"], 7_000, {"TNR-LSR-1": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 7_000, {"MON-27Q-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_eleventh_tenth_of_the_budget(gw):
    m = gw.mandate(budget=10_000)
    for n in range(10):
        assert gw.pay(m["token"], 1_000, {"STA-A4-5": 1, "batch": f"b{n}"}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 1_000, {"STA-A4-5": 1, "batch": "eleventh"}), 402, snap)


@pytest.mark.agent
def test_one_paisa_over_the_cap_in_a_single_payment(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 10_001, {"UPS-1KV-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_one_paisa_over_what_is_left(gw):
    m = gw.mandate(budget=10_000)
    gw.pay(m["token"], 6_000, {"KVM-DCK-1": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 4_001, {"HDS-ANC-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_one_paisa_payments_cannot_walk_past_a_tiny_cap(gw):
    m = gw.mandate(budget=5)
    for n in range(5):
        assert gw.pay(m["token"], 1, {"penny": f"p{n}"}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 1, {"penny": "sixth"}), 402, snap, audit="pay")


@pytest.mark.agent
def test_largest_allowed_amount_against_a_small_mandate(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], gateway.MAX_PAISE, {"SRV-RCK-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_root_token_still_capped_after_children_spent(gw):
    m = gw.mandate(budget=10_000)
    child = gw.delegate(m["token"], budget=6_000)
    gw.pay(child, 6_000, {"CBL-CAT6-1": 2})
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 5_000, {"DSK-ADJ-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_sibling_payers_share_one_mandate_ceiling(gw):
    m = gw.mandate(budget=10_000)
    apex = gw.delegate(m["token"], budget=8_000, to="aip:web:pocketchange.dev/payer/apex")
    north = gw.delegate(m["token"], budget=8_000, to="aip:web:pocketchange.dev/payer/north")
    assert gw.pay(apex, 8_000, {"MON-27Q-1": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(north, 8_000, {"KVM-DCK-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_mandate_never_opened_in_the_ledger(gw):
    from datetime import datetime, timedelta, timezone

    root = token.mint(gw.state.principal, budget_paise=50_000, max_depth=3,
                      expires=datetime.now(timezone.utc) + timedelta(hours=1))
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(root), 1_000), 404, snap, audit="pay")


# --- delegated envelopes are cumulative ----------------------------------------

@pytest.mark.agent
def test_sub_payer_pays_its_whole_cap_twice_with_different_carts(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000, to="aip:web:pocketchange.dev/payer/apex")
    assert gw.pay(sub, 1_000, {"STA-A4-5": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 1_000, {"CBL-CAT6-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_sub_payer_splits_its_cap_then_asks_for_a_third_half(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000)
    gw.pay(sub, 500, {"STA-A4-5": 1})
    gw.pay(sub, 500, {"TNR-LSR-1": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 500, {"CBL-CAT6-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_sub_payer_one_payment_over_its_own_cap(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 1_001, {"STA-A4-5": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_two_grandchildren_each_claim_the_childs_full_cap(gw):
    m = gw.mandate(budget=100_000)
    branch = gw.delegate(m["token"], tools=("delegate", "pay"), budget=4_000)
    first = gw.delegate(branch, budget=4_000)
    second = gw.delegate(branch, budget=4_000)
    assert gw.pay(first, 4_000, {"TNR-LSR-1": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(second, 4_000, {"STA-A4-5": 2}), 402, snap, audit="pay")


@pytest.mark.agent
def test_exhausted_sub_payer_narrows_itself_offline_for_a_fresh_allowance(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000)
    gw.pay(sub, 1_000, {"STA-A4-5": 1})
    fresh = _narrow_offline(gw, sub, 1_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(fresh, 1_000, {"TNR-LSR-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_offline_child_claiming_more_than_its_parent(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000)
    wider = _narrow_offline(gw, sub, 50_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(wider, 5_000, {"MON-27Q-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_mints_two_payers_each_at_the_brokers_full_budget(gw):
    m = gw.mandate(budget=100_000)
    broker = gw.delegate(m["token"], tools=("delegate", "pay"), budget=6_000,
                         to="aip:web:pocketchange.dev/broker")
    a = gw.delegate(broker, budget=6_000, to="aip:web:pocketchange.dev/payer/apex")
    b = gw.delegate(broker, budget=6_000, to="aip:web:pocketchange.dev/payer/vector")
    assert gw.pay(a, 6_000, {"KVM-DCK-1": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(b, 6_000, {"HDS-ANC-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_deepest_leaf_still_bound_by_a_middle_envelope(gw):
    m = gw.mandate(budget=100_000, depth=4)
    one = gw.delegate(m["token"], tools=("delegate", "pay"), budget=50_000)
    two = gw.delegate(one, tools=("delegate", "pay"), budget=3_000)
    leaf_a = gw.delegate(two, budget=3_000)
    leaf_b = gw.delegate(two, budget=3_000)
    gw.pay(leaf_a, 2_000, {"STA-A4-5": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(leaf_b, 2_000, {"TNR-LSR-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_sellers_under_their_caps_but_over_the_mandate(gw):
    m = gw.mandate(budget=10_000)
    apex = gw.delegate(m["token"], budget=7_000)
    north = gw.delegate(m["token"], budget=7_000)
    gw.pay(apex, 7_000, {"MON-27Q-1": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(north, 4_000, {"CBL-CAT6-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_zero_budget_child_pays_one_paisa(gw):
    m = gw.mandate(budget=10_000)
    looker = gw.delegate(m["token"], tools=("pay", "search"), budget=0)
    snap = gw.snapshot()
    gw.blocked(gw.pay(looker, 1, {"STA-A4-5": 1}), 403, snap, audit="pay")


# --- minting more than you hold ------------------------------------------------

@pytest.mark.agent
def test_delegate_a_child_bigger_than_the_mandate(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": 10_001, "context": "a bit more"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_delegate_a_grandchild_bigger_than_its_parent(gw):
    m = gw.mandate(budget=100_000)
    branch = gw.delegate(m["token"], tools=("delegate", "pay"), budget=2_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": branch, "tools": ["pay"],
                                         "budget_paise": 90_000, "context": "promote me"})
    gw.blocked(r, 403, snap, audit="delegate")


# --- races ---------------------------------------------------------------------

def _race(gw, tok, amount, carts):
    results = []

    def go(cart):
        client = TestClient(gateway.app, raise_server_exceptions=False)
        results.append(client.post("/pay", headers={"X-AIP-Token": tok}, json={
            "amount_paise": amount, "cart": cart, "context": "restocking"}).status_code)

    threads = [threading.Thread(target=go, args=(c,)) for c in carts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


@pytest.mark.agent
def test_eight_parallel_payments_each_sixty_percent_of_the_mandate(gw):
    m = gw.mandate(budget=10_000)
    results = _race(gw, m["token"], 6_000, [{"lane": f"l{n}"} for n in range(8)])
    assert results.count(200) == 1
    assert 500 not in results
    assert gw.state.ledger.state(m["mandate_id"]).committed_paise == 6_000
    assert len(gw.state.rail.orders) == 1


@pytest.mark.agent
def test_eight_parallel_payments_against_one_sub_payer_envelope(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=1_000)
    results = _race(gw, sub, 600, [{"lane": f"l{n}"} for n in range(8)])
    assert results.count(200) == 1
    assert 500 not in results
    assert len(gw.state.rail.orders) == 1


@pytest.mark.agent
def test_eight_parallel_copies_of_the_same_cart(gw):
    m = gw.mandate(budget=100_000)
    results = _race(gw, m["token"], 3_000, [{"STA-A4-5": 2}] * 8)
    assert 500 not in results
    assert len(gw.state.rail.orders) == 1
    assert gw.state.ledger.state(m["mandate_id"]).committed_paise == 3_000


# --- repurchase and failure paths ---------------------------------------------

@pytest.mark.agent
def test_repurchase_when_the_mandate_is_spent(gw):
    m = gw.mandate(budget=5_000)
    gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1})
    snap = gw.snapshot()
    r = gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1}, repurchase=True)
    gw.blocked(r, 402, snap, audit="pay")


@pytest.mark.agent
def test_repurchase_when_the_sub_payer_envelope_is_spent(gw):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=3_000)
    gw.pay(sub, 3_000, {"TNR-LSR-1": 1})
    snap = gw.snapshot()
    r = gw.pay(sub, 3_000, {"TNR-LSR-1": 1}, repurchase=True)
    gw.blocked(r, 402, snap, audit="pay")


@pytest.mark.agent
def test_rail_failure_does_not_leave_spend_or_a_hold(gw, monkeypatch):
    m = gw.mandate(budget=10_000)
    sub = gw.delegate(m["token"], budget=5_000)

    def refuse(**_):
        raise PaymentError("rail down")

    monkeypatch.setattr(gw.state.rail, "create_order", refuse)
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 5_000, {"UPS-1KV-1": 1}), 502, snap, audit="pay")


@pytest.mark.agent
def test_failed_rail_attempt_cannot_be_used_to_double_the_envelope(gw, monkeypatch):
    m = gw.mandate(budget=100_000)
    sub = gw.delegate(m["token"], budget=5_000)
    original = gw.state.rail.create_order
    calls = {"n": 0}

    def flaky(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PaymentError("timeout")
        return original(**kw)

    monkeypatch.setattr(gw.state.rail, "create_order", flaky)
    gw.pay(sub, 5_000, {"UPS-1KV-1": 1})
    assert gw.pay(sub, 5_000, {"UPS-1KV-1": 1}).status_code == 200
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 5_000, {"KVM-DCK-1": 1}), 402, snap, audit="pay")


# --- naming your own numbers ---------------------------------------------------

@pytest.mark.agent
@pytest.mark.parametrize("field,value", [
    pytest.param("budget_paise", 10**9, id="pay_body_claims_a_bigger_budget"),
    pytest.param("remaining_paise", 10**9, id="pay_body_claims_more_remaining"),
    pytest.param("cap_paise", 10**9, id="pay_body_claims_a_bigger_cap"),
    pytest.param("committed_paise", 0, id="pay_body_claims_nothing_committed"),
    pytest.param("mandate_id", "someone-elses-mandate", id="pay_body_names_another_mandate"),
])
def test_agent_cannot_state_its_own_budget_facts(gw, field, value):
    m = gw.mandate(budget=10_000)
    gw.pay(m["token"], 10_000, {"UPS-1KV-1": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 5_000, {"KVM-DCK-1": 1}, **{field: value}), 422, snap,
               audit=False)


@pytest.mark.agent
def test_payment_charged_to_the_header_token_not_a_richer_body_token(gw):
    poor = gw.mandate(budget=1_000)
    rich = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    r = gw.pay(poor["token"], 50_000, {"MON-27Q-1": 1}, aip_token=rich["token"])
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_payout_does_not_draw_on_the_mandate(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    r = gw.agent.post("/payout", headers={"X-AIP-Token": m["token"]}, json={
        "account": "acc_supplier_refund", "amount_paise": 5_000,
        "context": "refund the supplier directly"})
    gw.blocked(r, 501, snap, audit="payout")
