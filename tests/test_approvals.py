"""Escalation that suspends and resumes.

Before this, an ESCALATE verdict released the reservation and returned 409 - a
refusal wearing a nicer word, because there was no way for a person to say yes.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import gateway
from pocketchange.approvals import ApprovalStore
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE


@pytest.fixture
def client():
    gateway.state = gateway.State()
    gateway.state.monitor = ScriptedMonitor(Verdict.ESCALATE, "40kg is not a household order")
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


@pytest.fixture
def mandate(client):
    return client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE, "purpose": "weekly groceries", "ttl_seconds": 3600,
    }).json()


def escalate(client, mandate, amount=359_600 * RUPEE, cart=None):
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": amount, "cart": cart or {"LAP-STD-1": 40},
        "context": "buying rice for the household",
    })
    assert r.status_code == 202
    return r.json()["detail"]["approval_id"]


def test_pending_approvals_are_listed(client, mandate):
    approval_id = escalate(client, mandate)
    pending = client.get("/approvals").json()["pending"]
    assert [a["approval_id"] for a in pending] == [approval_id]
    assert pending[0]["reason"]
    # The agent's own account travels with it, so a human sees what was claimed.
    assert pending[0]["agent_claim"]


def test_approving_resumes_the_payment(client, mandate):
    approval_id = escalate(client, mandate)
    r = client.post(f"/approvals/{approval_id}",
                    json={"decision": "approve", "by": "somay", "note": "confirmed"})
    assert r.status_code == 200
    assert r.json()["status"] == "approved"
    assert r.json()["order_id"]

    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["committed_paise"] == 359_600 * RUPEE
    assert state["reserved_paise"] == 0


def test_denying_releases_the_budget(client, mandate):
    approval_id = escalate(client, mandate)
    r = client.post(f"/approvals/{approval_id}", json={"decision": "deny", "note": "too much"})
    assert r.json()["status"] == "denied"

    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["committed_paise"] == 0
    assert state["reserved_paise"] == 0
    assert state["available_paise"] == 600_000 * RUPEE


def test_a_decision_is_not_revisited(client, mandate):
    approval_id = escalate(client, mandate)
    client.post(f"/approvals/{approval_id}", json={"decision": "approve"})
    again = client.post(f"/approvals/{approval_id}", json={"decision": "deny"})
    assert again.status_code == 409


def test_unknown_approval(client):
    assert client.post("/approvals/ap_nope", json={"decision": "approve"}).status_code == 404


def test_an_unanswered_approval_expires_and_releases(client, mandate):
    """Held budget that never expires is a way to lock a mandate up and walk away."""
    gateway.state.approvals = ApprovalStore(ttl=timedelta(seconds=-1))
    escalate(client, mandate)

    assert client.get("/approvals").json()["pending"] == []
    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["reserved_paise"] == 0
    assert state["available_paise"] == 600_000 * RUPEE

    reasons = [e["reason"] for e in client.get("/audit").json()["entries"]]
    assert any("expired before anyone answered" in r for r in reasons)


def test_escalation_is_recorded_distinctly_from_a_refusal(client, mandate):
    escalate(client, mandate)
    decisions = [e["decision"] for e in client.get("/audit").json()["entries"]]
    assert "escalated" in decisions
    assert "denied" not in decisions


def test_a_resumed_payment_takes_the_same_settle_path(client, mandate):
    """A resume must not be a second implementation of the payment step."""
    approval_id = escalate(client, mandate)
    client.post(f"/approvals/{approval_id}", json={"decision": "approve"})
    paid = [e for e in client.get("/audit").json()["entries"]
            if e["decision"] == "allowed" and e["tool"] == "pay"]
    assert len(paid) == 1
    assert paid[0]["detail"]["order_id"]
    assert paid[0]["detail"]["approved_by"]


# --- policies use the same queue -------------------------------------------


def _policy(monkeypatch):
    """A plausible policy, so these tests exercise the queue not the model."""
    from agent.nodes.standing_node import PolicyLine, StandingPolicy, standing_chain

    monkeypatch.setattr(standing_chain, "invoke", lambda _v: StandingPolicy(
        reasoning="a small office gets through paper and toner",
        assumptions=["roughly a ream a week"],
        lines=[PolicyLine(sku="STA-A4-5", reorder_point=3, target_level=12,
                          rationale="paper runs out"),
               PolicyLine(sku="SRV-RCK-1", reorder_point=1, target_level=3,
                          rationale="poisoned: recurring servers")],
    ))


def draft(client):
    return client.post("/standing", json={
        "instruction": "keep the stationery cupboard stocked",
        "department": "operations", "period": "month",
        "budget_paise": 50_000 * RUPEE,
    }).json()


def test_a_policy_waits_in_the_same_queue(client, monkeypatch):
    _policy(monkeypatch)
    body = draft(client)
    assert body["status"] == "pending_approval"

    pending = client.get("/approvals").json()["pending"]
    kinds = {a["kind"] for a in pending}
    assert kinds == {"policy"}
    assert pending[0]["subject_id"] == body["standing_order"]["id"]


def test_a_drafted_policy_is_inert(client, monkeypatch):
    _policy(monkeypatch)
    draft(client)
    assert client.get("/standing").json()["orders"] == []


def test_approving_activates_it(client, monkeypatch):
    _policy(monkeypatch)
    body = draft(client)
    r = client.post(f"/approvals/{body['approval_id']}",
                    json={"decision": "approve", "by": "somay"})
    assert r.json()["kind"] == "policy"
    assert r.json()["status"] == "approved"

    running = client.get("/standing").json()["orders"]
    assert [o["id"] for o in running] == [body["standing_order"]["id"]]


def test_denying_leaves_it_inert(client, monkeypatch):
    _policy(monkeypatch)
    body = draft(client)
    client.post(f"/approvals/{body['approval_id']}", json={"decision": "deny"})
    assert client.get("/standing").json()["orders"] == []


def test_what_the_policy_refused_is_shown_to_the_approver(client, monkeypatch):
    """A person approving recurring authority should see what it does not cover."""
    _policy(monkeypatch)
    body = draft(client)
    rejected = [n for n in body["standing_order"]["notes"] if n.startswith("rejected")]
    assert any("SRV-RCK-1" in note for note in rejected)

    entry = [e for e in client.get("/audit").json()["entries"]
             if e["tool"] == "standing"][0]
    assert entry["decision"] == "escalated"
    assert entry["detail"]["rejected"]


def test_a_policy_covering_nothing_is_refused_outright(client, monkeypatch):
    from agent.nodes.standing_node import PolicyLine, StandingPolicy, standing_chain

    monkeypatch.setattr(standing_chain, "invoke", lambda _v: StandingPolicy(
        reasoning="", assumptions=[],
        lines=[PolicyLine(sku="SRV-RCK-1", reorder_point=1, target_level=3,
                          rationale="servers only")],
    ))
    r = client.post("/standing", json={
        "instruction": "keep the racks stocked", "department": "engineering",
        "period": "month", "budget_paise": 5_000_000 * RUPEE,
    })
    assert r.status_code == 422
    assert "no usable reorder rules" in r.json()["detail"]


def test_an_unapproved_policy_expires_without_touching_the_ledger(client, monkeypatch):
    """Nothing is held while a person thinks, so expiry releases nothing."""
    from datetime import timedelta

    from pocketchange.approvals import ApprovalStore

    _policy(monkeypatch)
    gateway.state.approvals = ApprovalStore(ttl=timedelta(seconds=-1))
    draft(client)

    assert client.get("/approvals").json()["pending"] == []
    reasons = [e["reason"] for e in client.get("/audit").json()["entries"]]
    assert any("expired before anyone approved" in r for r in reasons)
