"""The agent registry as a control, not a catalogue.

Two independent bounds on authority, and they fail differently:

  attenuation   a token cannot exceed its parent          cryptographic
  registry      an agent cannot exceed its approved card  organisational

A bug in one must not silently disable the other, which is the whole reason for
having both.
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import gateway
from pocketchange.policy import RUPEE
from pocketchange.registry import AgentCard, AgentRegistry, ExceedsCard, UnknownAgent


def card(name="buyer", version="1.0.0", department="engineering",
         identity="aip:web:x/buyer", capabilities=("search",), budget=100_000 * RUPEE):
    return AgentCard(name=name, version=version, department=department, owner="team",
                     identity=identity, capabilities=capabilities, max_budget_paise=budget)


@pytest.fixture
def registry():
    return AgentRegistry()


@pytest.fixture
def client():
    gateway.state = gateway.State()
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


# --- publishing and versioning ---------------------------------------------


def test_a_version_is_not_overwritten(registry):
    """An agent whose capabilities changed is a different agent."""
    registry.publish(card())
    with pytest.raises(Exception, match="already published"):
        registry.publish(card(capabilities=("search", "pay")))


def test_latest_version_is_returned_by_default(registry):
    registry.publish(card(version="1.0.0"))
    registry.publish(card(version="1.2.0"))
    assert registry.get("buyer").version == "1.2.0"
    assert registry.get("buyer", "1.0.0").version == "1.0.0"


def test_unknown_agent(registry):
    with pytest.raises(UnknownAgent):
        registry.get("nobody")


# --- discovery across departments ------------------------------------------


def test_discovery_by_capability_and_department(registry):
    registry.publish(card(name="shopper", identity="aip:web:x/s", capabilities=("search", "cart")))
    registry.publish(card(name="broker", department="finance", identity="aip:web:x/b",
                          capabilities=("delegate", "pay")))
    assert [c.name for c in registry.discover(capability="pay")] == ["broker"]
    assert [c.name for c in registry.discover(department="engineering")] == ["shopper"]
    assert registry.departments() == ["engineering", "finance"]


# --- the bound it actually enforces ----------------------------------------


def test_a_capability_off_the_card_is_refused(registry):
    registry.publish(card(capabilities=("search", "cart")))
    with pytest.raises(ExceedsCard, match="not approved for"):
        registry.check_grant("aip:web:x/buyer", ("pay",), 100)


def test_a_budget_above_the_card_is_refused(registry):
    registry.publish(card(budget=50_000 * RUPEE))
    with pytest.raises(ExceedsCard, match="may hold at most"):
        registry.check_grant("aip:web:x/buyer", ("search",), 60_000 * RUPEE)


def test_an_unapproved_agent_cannot_be_granted_anything(registry):
    registry.publish(AgentCard(
        name="draft", version="0.1.0", department="engineering", owner="team",
        identity="aip:web:x/draft", capabilities=("search",),
        max_budget_paise=100, approved=False,
    ))
    with pytest.raises(ExceedsCard, match="not approved"):
        registry.check_grant("aip:web:x/draft", ("search",), 1)


def test_unregistered_identities_pass_through(registry):
    """Ephemeral sub-agents are minted per purchase and bounded by attenuation.

    Pre-registering something that lives ten minutes would be paperwork, not
    governance.
    """
    registry.check_grant("aip:key:ed25519:whatever", ("pay",), 10_000_000)


# --- through the gateway ----------------------------------------------------


def test_the_standard_fleet_is_published(client):
    body = client.get("/agents").json()
    names = {a["ref"] for a in body["agents"]}
    assert names == {"procurement-shopper@1.0.0", "procurement-broker@1.0.0"}
    assert body["departments"] == ["engineering", "finance"]


def test_discovery_endpoint_filters(client):
    payers = client.get("/agents", params={"capability": "pay"}).json()["agents"]
    assert [a["ref"] for a in payers] == ["procurement-broker@1.0.0"]


def test_delegation_beyond_a_card_is_refused_by_the_gateway(client):
    """The registry bound, enforced where authority is actually minted."""
    mandate = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE, "purpose": "Q3 procurement", "ttl_seconds": 3600,
    }).json()
    r = client.post("/delegate", json={
        "token": mandate["token"], "tools": ["pay"], "budget_paise": 10_000 * RUPEE,
        "context": "granting the shopper the ability to spend",
        "to": "aip:web:pocketchange.dev/shopper",
    })
    assert r.status_code == 403
    assert "not approved for" in r.json()["detail"]["denied"]


def test_a_grant_within_the_card_is_allowed(client):
    mandate = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE, "purpose": "Q3 procurement", "ttl_seconds": 3600,
    }).json()
    r = client.post("/delegate", json={
        "token": mandate["token"], "tools": ["search", "cart"],
        "budget_paise": 200_000 * RUPEE, "context": "engineering requisitions",
        "to": "aip:web:pocketchange.dev/shopper",
    })
    assert r.status_code == 200


def test_publishing_through_the_gateway(client):
    r = client.post("/agents", json={
        "name": "marketing-shopper", "version": "1.0.0", "department": "marketing",
        "owner": "brand-team", "identity": "aip:web:pocketchange.dev/marketing",
        "capabilities": ["search", "cart"], "max_budget_paise": 150_000 * RUPEE,
    })
    assert r.status_code == 200
    assert "marketing" in client.get("/agents").json()["departments"]
