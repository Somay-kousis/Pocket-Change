"""Audit tampering and the trail's own integrity.

The log is hash-linked: each entry carries the hash of the one before it, so an
altered or removed entry breaks every hash after it and /audit/verify catches it.
What the attacker wants is a settled payment that leaves no trace, or a denial
that can be edited away. Neither is reachable from outside the process; the
verify cases prove the chain notices in-process tampering too.
"""

import pytest

from pocketchange.audit import AuditLog, Decision
from pocketchange import gateway


# --- every outcome is recorded ----------------------------------------------------

@pytest.mark.agent
def test_a_denied_payment_is_in_the_trail(gw):
    m = gw.mandate(budget=1_000)
    before = len(gw.state.audit)
    gw.pay(m["token"], 5_000, {"MON-27Q-1": 1})
    fresh = gw.state.audit.entries()[before:]
    assert any(e.decision is Decision.DENIED and e.tool == "pay" for e in fresh)
    assert gw.agent.get("/audit/verify").json()["ok"] is True


@pytest.mark.network
def test_a_forged_payment_is_in_the_trail(gw):
    before = len(gw.state.audit)
    gw.pay("AAAA", 5_000, {"MON-27Q-1": 1})
    fresh = gw.state.audit.entries()[before:]
    assert any(e.decision is Decision.DENIED for e in fresh)


@pytest.mark.agent
def test_settled_and_denied_both_recorded_across_a_mandate(gw):
    m = gw.mandate(budget=6_000)
    gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1})
    gw.pay(m["token"], 5_000, {"MON-27Q-1": 1})
    decisions = [e.decision for e in gw.state.audit.entries(m["mandate_id"])]
    assert Decision.ALLOWED in decisions and Decision.DENIED in decisions


# --- the trail cannot be written or cleared from outside --------------------------

@pytest.mark.network
def test_no_endpoint_appends_an_audit_entry(gw):
    before = len(gw.state.audit)
    for method, path in [("post", "/audit"), ("delete", "/audit"), ("put", "/audit/0"),
                         ("post", "/audit/verify")]:
        getattr(gw.agent, method)(path)
    # Only the natural read-path verify may have run; nothing wrote an entry.
    assert all(e.tool != "audit" for e in gw.state.audit.entries()[before:])


@pytest.mark.network
def test_events_endpoint_does_not_touch_the_audit(gw):
    before = len(gw.state.audit)
    gw.agent.post("/events", json={"node_id": "n", "kind": "settled",
                                   "detail": {"order_id": "order_fake_9999"}})
    assert len(gw.state.audit) == before


@pytest.mark.network
def test_a_fabricated_settled_event_creates_no_payment(gw):
    snap = gw.snapshot()
    gw.agent.post("/events", json={"node_id": "leaf", "kind": "settled",
                                   "detail": {"amount_paise": 500000}})
    gw.unmoved(snap)


# --- in-process tampering is evident ----------------------------------------------

def _chain_with(n=3):
    log = AuditLog()
    for i in range(n):
        log.append(mandate_id="m", actor="a", tool="pay", decision=Decision.ALLOWED,
                   reason=f"entry {i}", context="c", amount_paise=100 * (i + 1))
    return log


@pytest.mark.agent
def test_editing_an_amount_breaks_the_chain():
    log = _chain_with()
    object.__setattr__(log._entries[1], "amount_paise", 999_999)
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_editing_a_decision_breaks_the_chain():
    log = _chain_with()
    object.__setattr__(log._entries[1], "decision", Decision.DENIED)
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_editing_a_reason_breaks_the_chain():
    log = _chain_with()
    object.__setattr__(log._entries[0], "reason", "something else entirely")
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_removing_an_entry_breaks_the_chain():
    log = _chain_with()
    del log._entries[1]
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_reordering_entries_breaks_the_chain():
    log = _chain_with()
    log._entries[1], log._entries[2] = log._entries[2], log._entries[1]
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_reinserting_an_entry_with_a_fresh_hash_still_breaks_the_seq():
    log = _chain_with()
    tampered = log._entries[1]
    object.__setattr__(tampered, "amount_paise", 1)
    object.__setattr__(tampered, "entry_hash", tampered.compute_hash())
    with pytest.raises(Exception):
        log.verify()


@pytest.mark.agent
def test_incident_view_reports_a_broken_chain(gw):
    m = gw.mandate(budget=6_000)
    seq = gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1}).json()["audit_seq"]
    object.__setattr__(gw.state.audit._entries[0], "amount_paise", 1)
    body = gw.agent.get(f"/incident/{seq}").json()
    assert body["record"]["chain_intact"] is False


@pytest.mark.agent
def test_verify_endpoint_reports_a_broken_chain(gw):
    m = gw.mandate(budget=6_000)
    gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1})
    object.__setattr__(gw.state.audit._entries[1], "reason", "nothing to see")
    assert gw.agent.get("/audit/verify").json()["ok"] is False


# --- a denial cannot masquerade as an approval ------------------------------------

@pytest.mark.agent
def test_monitor_unconfigured_is_not_recorded_as_approved(gw):
    m = gw.mandate(budget=10_000)
    seq = gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1}).json()["audit_seq"]
    entry = next(e for e in gw.state.audit.entries() if e.seq == seq)
    assert entry.detail.get("monitor_ran") is False
    assert entry.detail.get("monitor") in ("skipped", "unconfigured")


@pytest.mark.agent
def test_incident_names_an_unreviewed_payment_as_unreviewed(gw):
    m = gw.mandate(budget=10_000)
    seq = gw.pay(m["token"], 5_000, {"TNR-LSR-1": 1}).json()["audit_seq"]
    judgement = gw.agent.get(f"/incident/{seq}").json()["judgement"]
    assert "NOT" in judgement["means"] or "not" in judgement["means"]


@pytest.mark.agent
def test_incident_for_a_sequence_that_does_not_exist(gw):
    snap = gw.snapshot()
    r = gw.agent.get("/incident/99999")
    assert r.status_code == 404
    gw.unmoved(snap)
