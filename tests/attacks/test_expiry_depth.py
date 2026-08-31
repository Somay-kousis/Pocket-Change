"""Expiry and depth.

Time is the gateway's clock, never the caller's. Depth is the number of signed
blocks, never a field in the body.
"""

from datetime import datetime, timedelta, timezone

import pytest

from pocketchange import token
from pocketchange.policy import Grant
from tests.attacks.conftest import LIMIT_NO_REVOCATION


def _expired_mandate(gw, seconds_ago=1, budget=50_000, depth=3):
    root = token.mint(gw.state.principal, budget_paise=budget, max_depth=depth,
                      expires=datetime.now(timezone.utc) - timedelta(seconds=seconds_ago))
    gw.state.ledger.open(token.mandate_id(root), budget)
    return token.serialize(root)


def _extend(gw, raw, n, budget=1_000):
    tok = token.deserialize(raw, gw.state.root_public_key)
    for i in range(n):
        tok = token.attenuate(tok, to=f"aip:web:pocketchange.dev/layer/{i}",
                              grant=Grant(("delegate", "pay"), budget), context="one more layer")
    return token.serialize(tok)


# --- expiry ----------------------------------------------------------------------

@pytest.mark.agent
def test_mandate_expired_one_second_ago(gw):
    tok = _expired_mandate(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_mandate_expired_a_day_ago(gw):
    tok = _expired_mandate(gw, seconds_ago=86_400)
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_child_of_an_expired_mandate(gw):
    tok = _extend(gw, _expired_mandate(gw), 1)
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 500), 403, snap, audit="pay")


@pytest.mark.agent
def test_delegating_from_an_expired_mandate(gw):
    tok = _expired_mandate(gw)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": tok, "tools": ["pay"],
                                         "budget_paise": 1_000, "context": "still valid?"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_short_lived_child_used_after_its_own_expiry(gw):
    m = gw.mandate()
    parent = token.deserialize(m["token"], gw.state.root_public_key)
    child = token.attenuate(parent, to="aip:web:pocketchange.dev/payer/x",
                            grant=Grant(("pay",), 5_000,
                                        expires=datetime.now(timezone.utc) - timedelta(seconds=1)),
                            context="ten minute mandate")
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(child), 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_expired_child_extends_itself_with_a_later_expiry(gw):
    m = gw.mandate()
    parent = token.deserialize(m["token"], gw.state.root_public_key)
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    child = token.attenuate(parent, to="x", grant=Grant(("pay",), 5_000, expires=past),
                            context="expired")
    later = token.attenuate(child, to="x", grant=Grant(("pay",), 5_000,
                                                       expires=past + timedelta(days=30)),
                            context="renewing myself")
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(later), 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_expired_mandate_child_with_its_own_future_expiry(gw):
    root = _expired_mandate(gw)
    parent = token.deserialize(root, gw.state.root_public_key)
    child = token.attenuate(parent, to="x", grant=Grant(
        ("pay",), 5_000, expires=datetime.now(timezone.utc) + timedelta(hours=1)),
        context="fresh child of a stale root")
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(child), 1_000), 403, snap, audit="pay")


@pytest.mark.agent
@pytest.mark.parametrize("field,value", [
    pytest.param("at", "2020-01-01T00:00:00Z", id="pay_body_names_an_earlier_time"),
    pytest.param("time", 0, id="pay_body_names_the_epoch"),
    pytest.param("expires", "2099-01-01T00:00:00Z", id="pay_body_names_a_later_expiry"),
])
def test_caller_cannot_supply_the_clock(gw, field, value):
    tok = _expired_mandate(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000, **{field: value}), 422, snap, audit=False)


@pytest.mark.agent
def test_child_ttl_longer_than_an_hour(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": 1_000, "context": "long life",
                                         "ttl_seconds": 3_601})
    gw.blocked(r, 422, snap, audit=False)


@pytest.mark.agent
def test_child_ttl_longer_than_its_parent_does_not_outlive_it(gw):
    m = gw.mandate(ttl=60)
    child = gw.delegate(m["token"], budget=1_000, ttl=3_600)
    parsed = token.deserialize(child, gw.state.root_public_key)
    from pocketchange.policy import Operation

    with pytest.raises(token.Denied):
        token.verify(parsed, Operation("pay", 1, depth=1,
                                       at=datetime.now(timezone.utc) + timedelta(seconds=120)))


@pytest.mark.agent
def test_expired_escalation_cannot_be_settled(gw):
    m = gw.mandate()
    approval = gw.escalate(m["token"], amount=5_000)
    gw.state.approvals.get(approval).expires_at = datetime.now(timezone.utc)
    gw.agent.get("/approvals")
    snap = gw.snapshot()
    r = gw.operator.post(f"/approvals/{approval}", json={"decision": "approve"})
    gw.blocked(r, 409, snap, audit=False)
    assert gw.state.ledger.state(m["mandate_id"]).reserved_paise == 0


# --- depth -----------------------------------------------------------------------

@pytest.mark.agent
def test_pay_one_layer_past_max_depth(gw):
    m = gw.mandate(depth=2)
    deep = _extend(gw, m["token"], 3)
    snap = gw.snapshot()
    gw.blocked(gw.pay(deep, 500), 403, snap, audit="pay")


@pytest.mark.agent
def test_pay_far_past_max_depth(gw):
    m = gw.mandate(depth=1)
    deep = _extend(gw, m["token"], 9)
    snap = gw.snapshot()
    gw.blocked(gw.pay(deep, 500), 403, snap, audit="pay")


@pytest.mark.agent
def test_delegate_at_the_depth_limit(gw):
    m = gw.mandate(depth=2)
    at_limit = _extend(gw, m["token"], 2)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": at_limit, "tools": ["pay"],
                                         "budget_paise": 100, "context": "one more"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
@pytest.mark.parametrize("claimed", [
    pytest.param(0, id="deep_token_claims_depth_zero"),
    pytest.param(1, id="deep_token_claims_depth_one"),
])
def test_claimed_depth_is_ignored_and_recorded(gw, claimed):
    m = gw.mandate(depth=2)
    deep = _extend(gw, m["token"], 3)
    snap = gw.snapshot()
    gw.blocked(gw.pay(deep, 500, depth=claimed), 403, snap, audit="pay")
    assert any("claimed depth" in e.reason for e in gw.denials_since(snap))


@pytest.mark.agent
def test_claimed_depth_on_delegate_is_ignored(gw):
    m = gw.mandate(depth=2)
    at_limit = _extend(gw, m["token"], 2)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": at_limit, "tools": ["pay"],
                                         "budget_paise": 100, "context": "x", "depth": 0})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_mandate_asking_for_more_than_eight_layers(gw):
    snap = gw.snapshot()
    r = gw.operator.post("/mandates", json={"budget_paise": 1_000, "purpose": "deep tree",
                                            "max_depth": 9})
    gw.blocked(r, 422, snap, audit=False)


@pytest.mark.agent
def test_offline_layer_cannot_raise_max_depth(gw):
    from biscuit_auth import BlockBuilder

    m = gw.mandate(depth=1)
    tok = token.deserialize(m["token"], gw.state.root_public_key)
    tok = tok.append(BlockBuilder("max_depth(100);"))
    deep = token.serialize(tok)
    deep = _extend(gw, deep, 2)
    snap = gw.snapshot()
    gw.blocked(gw.pay(deep, 500), 403, snap, audit="pay")


# --- what the README already says we cannot stop --------------------------------

@pytest.mark.agent
@pytest.mark.xfail(strict=True, reason=LIMIT_NO_REVOCATION)
def test_leaked_token_keeps_spending_after_the_operator_wants_it_stopped(gw):
    m = gw.mandate()
    # No route exists to withdraw a live mandate; this is what one would do.
    gw.operator.post(f"/mandates/{m['mandate_id']}/revoke")
    snap = gw.snapshot()
    r = gw.pay(m["token"], 1_000)
    assert r.status_code in (401, 403)
    gw.unmoved(snap)
