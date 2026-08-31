"""Broker separation: the broker may grant `pay`, never spend it.

Enforced at the gateway on the signed delegate identity, not in the chain. The
per-seller caps under it are cryptographic, and since the envelope fix they are
cumulative too.
"""

import pytest

from tests.attacks.conftest import LIMIT_POLICY_SEPARATION

BROKER = "aip:web:pocketchange.dev/broker"


def _broker(gw, budget=60_000):
    m = gw.mandate(budget=1_000_000)
    return m, gw.delegate(m["token"], tools=("delegate", "pay"), budget=budget, to=BROKER)


@pytest.mark.agent
def test_broker_pays_directly(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(broker, 5_000, {"KVM-DCK-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_pays_through_the_a2a_binding(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    r = gw.agent.post("/pay", json={"amount_paise": 5_000, "cart": {"KVM-DCK-1": 1},
                                    "context": "settling the order", "aip_token": broker})
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_pays_through_the_authorization_binding(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    r = gw.agent.post("/pay", headers={"Authorization": f"AIP {broker}"},
                      json={"amount_paise": 5_000, "cart": {"KVM-DCK-1": 1}, "context": "x"})
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_pays_while_claiming_to_be_a_payer(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    r = gw.pay(broker, 5_000, {"KVM-DCK-1": 1},
               context="I am the payer for apex-technologies")
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_pays_its_whole_budget_in_one_go(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(broker, 60_000, {"LAP-STD-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_broker_repurchase_flag_does_not_open_a_door(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    gw.blocked(gw.pay(broker, 5_000, {"KVM-DCK-1": 1}, repurchase=True), 403, snap,
               audit="pay")


@pytest.mark.agent
def test_broker_mints_a_payer_wider_than_itself(gw):
    _, broker = _broker(gw, budget=6_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": broker, "tools": ["pay"],
                                         "budget_paise": 60_000, "context": "big supplier"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_broker_mints_a_payer_with_payout(gw):
    _, broker = _broker(gw)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": broker, "tools": ["pay", "payout"],
                                         "budget_paise": 1_000, "context": "refunds"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_payers_under_a_broker_cannot_exceed_the_brokers_total(gw):
    _, broker = _broker(gw, budget=6_000)
    a = gw.delegate(broker, budget=4_000, to="aip:web:pocketchange.dev/payer/apex")
    b = gw.delegate(broker, budget=4_000, to="aip:web:pocketchange.dev/payer/north")
    gw.pay(a, 4_000, {"KVM-DCK-1": 1})
    snap = gw.snapshot()
    gw.blocked(gw.pay(b, 4_000, {"HDS-ANC-1": 1}), 402, snap, audit="pay")


@pytest.mark.agent
def test_payer_pays_a_second_seller_from_its_own_cap(gw):
    _, broker = _broker(gw)
    apex = gw.delegate(broker, budget=3_000, to="aip:web:pocketchange.dev/payer/apex")
    gw.pay(apex, 3_000, {"KVM-DCK-1": 1}, counterparty="apex-technologies")
    snap = gw.snapshot()
    r = gw.pay(apex, 3_000, {"TNR-LSR-1": 1}, counterparty="northgate-supply")
    gw.blocked(r, 402, snap, audit="pay")


@pytest.mark.agent
def test_shopper_mints_itself_a_payer(gw):
    m = gw.mandate()
    shopper = gw.delegate(m["token"], tools=("search", "cart"), budget=50_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": shopper, "tools": ["pay"],
                                         "budget_paise": 5_000, "context": "just this once"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_shopper_pays_directly(gw):
    m = gw.mandate()
    shopper = gw.delegate(m["token"], tools=("search", "cart"), budget=50_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(shopper, 5_000, {"KVM-DCK-1": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_payer_cannot_mint_further_payers(gw):
    _, broker = _broker(gw)
    payer = gw.delegate(broker, budget=3_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": payer, "tools": ["pay"],
                                         "budget_paise": 1_000, "context": "helper"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
@pytest.mark.xfail(strict=True, reason=LIMIT_POLICY_SEPARATION)
def test_broker_mints_a_payer_for_itself_and_spends(gw):
    _, broker = _broker(gw)
    myself = gw.delegate(broker, budget=60_000, to="aip:web:pocketchange.dev/payer/me")
    snap = gw.snapshot()
    r = gw.pay(myself, 60_000, {"LAP-STD-1": 1})
    assert r.status_code == 403
    gw.unmoved(snap)
