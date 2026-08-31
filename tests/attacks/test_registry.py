"""Agent registry: a named agent cannot be granted more than its card says.

Also: publishing a card is the operator's act. Cards are published approved,
and POST /agents used to accept them from anyone.
"""

import pytest

from tests.attacks.conftest import LIMIT_DEMO_GATE

SHOPPER = "aip:web:pocketchange.dev/shopper"
BROKER = "aip:web:pocketchange.dev/broker"


def _grant(gw, parent, to, tools, budget):
    return gw.agent.post("/delegate", json={"token": parent, "to": to, "tools": tools,
                                            "budget_paise": budget, "context": "staffing"})


def _card(**over):
    card = {"name": "procurement-shopper", "version": "9.0.0", "department": "engineering",
            "owner": "platform-team", "identity": SHOPPER,
            "capabilities": ["search", "cart", "pay"], "max_budget_paise": 10**9}
    return {**card, **over}


# --- grants beyond a published card -------------------------------------------

@pytest.mark.agent
def test_shopper_identity_granted_pay(gw):
    m = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], SHOPPER, ["search", "pay"], 1_000), 403, snap,
               audit="delegate")


@pytest.mark.agent
def test_shopper_identity_granted_delegate(gw):
    m = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], SHOPPER, ["search", "delegate"], 0), 403, snap,
               audit="delegate")


@pytest.mark.agent
def test_shopper_identity_granted_payout(gw):
    m = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], SHOPPER, ["payout"], 1_000), 403, snap,
               audit="delegate")


@pytest.mark.agent
def test_broker_identity_granted_payout(gw):
    m = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], BROKER, ["delegate", "pay", "payout"], 1_000), 403,
               snap, audit="delegate")


@pytest.mark.agent
def test_broker_identity_one_paisa_over_its_card(gw):
    m = gw.mandate(budget=100_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], BROKER, ["delegate", "pay"], 600_000 * 100 + 1), 403,
               snap, audit="delegate")


@pytest.mark.agent
def test_shopper_identity_with_duplicated_allowed_tools_plus_pay(gw):
    m = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    gw.blocked(_grant(gw, m["token"], SHOPPER, ["search", "search", "cart", "pay"], 1_000),
               403, snap, audit="delegate")


# --- publishing cards without the operator ------------------------------------

@pytest.mark.agent
def test_agent_publishes_a_wider_version_of_its_own_card(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/agents", json=_card())
    gw.blocked(r, 401, snap, audit="registry")
    assert "9.0.0" not in [c["ref"].split("@")[1] for c in gw.agent.get("/agents").json()["agents"]]


@pytest.mark.network
def test_network_caller_publishes_a_new_paying_agent(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/agents", json=_card(name="helpful-payer", version="1.0.0",
                                            identity="aip:web:attacker.example/payer"))
    gw.blocked(r, 401, snap, audit="registry")


@pytest.mark.network
def test_network_caller_publishes_a_blocking_card_for_a_payer_identity(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/agents", json=_card(
        name="payer-apex", version="1.0.0", capabilities=["search"], max_budget_paise=0,
        identity="aip:web:pocketchange.dev/payer/apex-technologies"))
    gw.blocked(r, 401, snap, audit="registry")


@pytest.mark.agent
def test_agent_uses_its_aip_token_as_the_operator_credential_to_publish(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/agents", headers={"X-Operator-Token": m["token"]}, json=_card())
    gw.blocked(r, 401, snap, audit="registry")


@pytest.mark.agent
def test_operator_cannot_be_tricked_into_overwriting_a_published_version(gw):
    snap = gw.snapshot()
    r = gw.operator.post("/agents", json=_card(version="1.0.0"))
    gw.blocked(r, 409, snap, audit=False)
    card = gw.agent.get("/agents/procurement-shopper", params={"version": "1.0.0"}).json()
    assert "pay" not in card["capabilities"]


# --- minting your own authority -------------------------------------------------

@pytest.mark.agent
def test_agent_mints_itself_a_fresh_mandate(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/mandates", json={"budget_paise": 10**9, "purpose": "more room"})
    gw.blocked(r, 401, snap, audit="mandate")
    assert len(gw.state.ledger._mandates) == 0


@pytest.mark.network
def test_network_caller_mints_a_mandate(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/mandates", json={"budget_paise": 5_000, "purpose": "groceries"})
    gw.blocked(r, 401, snap, audit="mandate")


@pytest.mark.agent
def test_agent_mints_a_mandate_with_its_own_token_as_credential(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/mandates", headers={"X-Operator-Token": m["token"]},
                      json={"budget_paise": 10**9, "purpose": "more room"})
    gw.blocked(r, 401, snap, audit="mandate")


@pytest.mark.agent
def test_mandate_minting_refuses_when_no_operator_is_configured(gw, monkeypatch):
    monkeypatch.delenv("POCKETCHANGE_OPERATOR_TOKEN")
    snap = gw.snapshot()
    r = gw.operator.post("/mandates", json={"budget_paise": 5_000, "purpose": "groceries"})
    gw.blocked(r, 503, snap, audit="mandate")


@pytest.mark.network
@pytest.mark.xfail(strict=True, reason=LIMIT_DEMO_GATE)
def test_network_caller_opens_a_mandate_through_runs(gw, monkeypatch):
    from pocketchange import gateway

    # The run itself is never started: only the mandate it opens is in question.
    monkeypatch.setattr(gateway.threading, "Thread",
                        lambda *a, **k: type("Idle", (), {"start": lambda self: None})())
    monkeypatch.setattr(gateway.threading, "Timer",
                        lambda *a, **k: type("Idle", (), {"start": lambda self: None,
                                                          "cancel": lambda self: None,
                                                          "daemon": False})())
    snap = gw.snapshot()
    r = gw.agent.post("/runs", json={"task": "kit out the studio", "budget_paise": 1_000_000,
                                     "critic": False, "monitor": False})
    assert r.status_code in (401, 403)
    gw.unmoved(snap)
