"""Replay and idempotency: one cart, one charge.

The idempotency key is derived from the mandate, the cart and the amount, never
from anything the caller chooses. Hole 2 was the window: replay records lived an
hour while mandates live a day, and the ledger handed back a settled
reservation, so the same cart after the window reached the rail twice.
"""

from datetime import timedelta
from types import SimpleNamespace

import pytest

from pocketchange import gateway, token
from pocketchange.monitor import Verdict

CART = {"TNR-LSR-1": 1, "STA-A4-5": 2}


def _first(gw, budget=100_000, amount=6_000, cart=CART):
    m = gw.mandate(budget=budget)
    r = gw.pay(m["token"], amount, cart)
    assert r.status_code == 200, r.text
    return m, r.json()


def _forget_window(gw):
    gw.state.replays._ttl = timedelta(0)


def _assert_one_charge(gw, m, amount=6_000):
    assert len(gw.state.rail.orders) == 1
    assert gw.state.ledger.state(m["mandate_id"]).committed_paise == amount


# --- inside the window: the original receipt, never a second charge -----------

@pytest.mark.agent
@pytest.mark.parametrize("variant", [
    pytest.param({}, id="identical_resend"),
    pytest.param({"context": "a completely different justification"}, id="resend_with_new_context"),
    pytest.param({"counterparty": "apex-technologies"}, id="resend_naming_a_counterparty"),
    pytest.param({"divergence": 2}, id="resend_reporting_divergence"),
    pytest.param({"depth": 0}, id="resend_claiming_depth_zero"),
])
def test_resend_returns_the_original_order(gw, variant):
    m, first = _first(gw)
    body = {"context": "restocking paper", **variant}
    r = gw.pay(m["token"], 6_000, CART, **body)
    assert r.status_code == 200 and r.json()["replayed"] is True
    assert r.json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_resend_with_cart_keys_reordered(gw):
    m, first = _first(gw)
    r = gw.pay(m["token"], 6_000, {"STA-A4-5": 2, "TNR-LSR-1": 1})
    assert r.json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_resend_with_nested_cart_keys_reordered(gw):
    cart = {"lines": {"b": {"qty": 1, "sku": "TNR-LSR-1"}, "a": {"qty": 2, "sku": "STA-A4-5"}}}
    m, first = _first(gw, cart=cart)
    shuffled = {"lines": {"a": {"sku": "STA-A4-5", "qty": 2}, "b": {"sku": "TNR-LSR-1", "qty": 1}}}
    assert gw.pay(m["token"], 6_000, shuffled).json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_resend_through_the_authorization_binding(gw):
    m, first = _first(gw)
    r = gw.agent.post("/pay", headers={"Authorization": f"AIP {m['token']}"},
                      json={"amount_paise": 6_000, "cart": CART, "context": "again"})
    assert r.json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_resend_through_the_a2a_body_binding(gw):
    m, first = _first(gw)
    r = gw.agent.post("/pay", json={"amount_paise": 6_000, "cart": CART,
                                    "context": "again", "aip_token": m["token"]})
    assert r.json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_resend_from_a_sibling_token_of_the_same_mandate(gw):
    m = gw.mandate()
    a = gw.delegate(m["token"], budget=50_000, to="aip:web:pocketchange.dev/payer/a")
    b = gw.delegate(m["token"], budget=50_000, to="aip:web:pocketchange.dev/payer/b")
    first = gw.pay(a, 6_000, CART).json()
    second = gw.pay(b, 6_000, CART).json()
    assert second["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
def test_caller_chosen_idempotency_header_is_ignored(gw):
    m, first = _first(gw)
    r = gw.agent.post("/pay", headers={"X-AIP-Token": m["token"], "Idempotency-Key": "fresh-1"},
                      json={"amount_paise": 6_000, "cart": CART, "context": "again"})
    assert r.json()["order_id"] == first["order_id"]
    _assert_one_charge(gw, m)


@pytest.mark.agent
@pytest.mark.parametrize("field", [
    pytest.param("idempotency_key", id="body_supplies_its_own_idempotency_key"),
    pytest.param("occurrence", id="body_supplies_its_own_occurrence_number"),
    pytest.param("nonce", id="body_supplies_a_nonce"),
])
def test_caller_cannot_choose_the_key(gw, field):
    m, _ = _first(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 6_000, CART, **{field: "fresh"}), 422, snap, audit=False)


# --- after the window: refused, never a second order ---------------------------

@pytest.mark.agent
def test_same_cart_after_the_replay_window(gw):
    m, _ = _first(gw)
    _forget_window(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 6_000, CART), 409, snap, audit="pay")


@pytest.mark.agent
def test_same_cart_after_the_window_from_a_sub_payer(gw):
    m = gw.mandate()
    sub = gw.delegate(m["token"], budget=50_000)
    gw.pay(sub, 6_000, CART)
    _forget_window(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(sub, 6_000, CART), 409, snap, audit="pay")


@pytest.mark.agent
def test_same_cart_after_the_window_with_new_wording(gw):
    m, _ = _first(gw)
    _forget_window(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"], 6_000, CART, context="this is a new order, honestly"),
               409, snap, audit="pay")


@pytest.mark.agent
def test_reused_occurrence_number_after_the_window(gw):
    m, _ = _first(gw)
    approval = gw.pay(m["token"], 6_000, CART, repurchase=True).json()["detail"]["approval_id"]
    gw.operator.post(f"/approvals/{approval}", json={"decision": "approve"})
    _forget_window(gw)
    snap = gw.snapshot()
    r = gw.pay(m["token"], 6_000, CART, repurchase=True)
    gw.blocked(r, 409, snap, audit="pay")


@pytest.mark.agent
def test_no_mandate_can_outlive_the_replay_window(gw):
    from pocketchange.idempotency import DEFAULT_TTL

    snap = gw.snapshot()
    r = gw.operator.post("/mandates", json={
        "budget_paise": 10_000, "purpose": "a mandate longer than the window",
        "ttl_seconds": int(DEFAULT_TTL.total_seconds()) + 1})
    gw.blocked(r, 422, snap, audit=False)
    assert len(gw.state.ledger._mandates) == 0


# --- repurchase is a question, not a charge -----------------------------------

@pytest.mark.agent
def test_repurchase_flag_alone_does_not_charge(gw):
    m, _ = _first(gw)
    snap = gw.snapshot()
    r = gw.pay(m["token"], 6_000, CART, repurchase=True)
    assert r.status_code == 202
    gw.unmoved(snap, reserved=False)


@pytest.mark.agent
def test_denied_escalation_then_resend_escalates_again(gw):
    m = gw.mandate()
    approval = gw.escalate(m["token"], amount=6_000, cart=CART)
    gw.operator.post(f"/approvals/{approval}", json={"decision": "deny"})
    gw.monitor(Verdict.ESCALATE, "still odd")
    snap = gw.snapshot()
    r = gw.pay(m["token"], 6_000, CART)
    assert r.status_code == 202
    gw.unmoved(snap, reserved=False)


# --- the replay endpoint, from the network -------------------------------------

def _funnel_payment(gw):
    m = gw.mandate()
    leaf = token.deserialize(gw.delegate(m["token"], budget=20_000), gw.state.root_public_key)
    node = SimpleNamespace(token=leaf, budget_paise=7_000, id="leaf-1",
                           description="toner for the studio", supplier=None)
    gateway._pay_internal(node, m["mandate_id"])
    seq = max(gateway._REPLAYABLE)
    return m, seq


@pytest.mark.network
def test_network_replay_of_a_settled_payment(gw):
    m, seq = _funnel_payment(gw)
    r = gw.agent.post(f"/replay/{seq}")
    assert r.status_code == 200 and r.json()["same_order"] is True
    assert r.json()["charged_twice"] is False
    _assert_one_charge(gw, m, 7_000)


@pytest.mark.network
def test_network_replay_after_the_window(gw):
    m, seq = _funnel_payment(gw)
    _forget_window(gw)
    snap = gw.snapshot()
    r = gw.agent.post(f"/replay/{seq}")
    assert r.status_code != 500
    gw.unmoved(snap)
    _assert_one_charge(gw, m, 7_000)


@pytest.mark.network
def test_network_replay_five_times(gw):
    m, seq = _funnel_payment(gw)
    for _ in range(5):
        gw.agent.post(f"/replay/{seq}")
    _assert_one_charge(gw, m, 7_000)


@pytest.mark.network
@pytest.mark.parametrize("seq", [
    pytest.param("999999", id="replay_of_a_sequence_never_written"),
    pytest.param("-1", id="replay_of_a_negative_sequence"),
    pytest.param("first", id="replay_of_a_word_not_a_sequence"),
])
def test_network_replay_of_nothing(gw, seq):
    snap = gw.snapshot()
    r = gw.agent.post(f"/replay/{seq}")
    gw.blocked(r, {404, 422}, snap, audit=False)


@pytest.mark.network
def test_network_replay_of_a_denial_is_not_a_payment(gw):
    m = gw.mandate(budget=1_000)
    denied = gw.pay(m["token"], 5_000, CART).json()["detail"]["audit_seq"]
    snap = gw.snapshot()
    gw.blocked(gw.agent.post(f"/replay/{denied}"), 404, snap, audit=False)
