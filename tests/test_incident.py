"""One payment, assembled for someone investigating it.

The failure this view exists to avoid is the one that runs through the rest of
the project: presenting something nobody established as though it were a fact.
An incident report that shows a broken chain as clean history, or an unreviewed
payment as an approved one, is worse than having no report - it converts an
open question into a wrong answer.
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import gateway
from pocketchange.policy import RUPEE


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("RAZORPAY_KEY_SECRET", raising=False)
    gateway.state = gateway.State()
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


@pytest.fixture
def paid(client):
    """A mandate with one settled payment. Returns (mandate, audit seq)."""
    m = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE,
        "purpose": "restock the stationery cupboard",
        "ttl_seconds": 3600,
    }).json()
    r = client.post("/pay", headers={"X-AIP-Token": m["token"]}, json={
        "amount_paise": 300 * RUPEE, "cart": {"STA-A4-5": 3},
        "context": "three reams of paper",
    })
    assert r.status_code == 200
    return m, r.json()["audit_seq"]


def test_an_unknown_sequence_is_a_404_not_an_empty_report(client):
    assert client.get("/incident/9999").status_code == 404


def test_it_reports_the_payment_and_the_mandate_that_authorised_it(client, paid):
    mandate, seq = paid
    body = client.get(f"/incident/{seq}").json()

    assert body["entry"]["seq"] == seq
    assert body["entry"]["amount_paise"] == 300 * RUPEE
    assert body["mandate"]["id"] == mandate["mandate_id"]
    assert body["mandate"]["intent"] == "restock the stationery cupboard"
    assert body["mandate"]["ledger"]["committed_paise"] == 300 * RUPEE


def test_it_shows_what_led_to_the_payment_in_order(client, paid):
    """The mandate being opened precedes the payment, and is reported as such."""
    _, seq = paid
    body = client.get(f"/incident/{seq}").json()

    before = body["leading_to_it"]
    assert before, "opening the mandate should appear before the payment"
    assert [e["seq"] for e in before] == sorted(e["seq"] for e in before)
    assert all(e["seq"] < seq for e in before)


def test_it_says_the_chain_is_intact_and_what_that_proves(client, paid):
    _, seq = paid
    record = client.get(f"/incident/{seq}").json()["record"]

    assert record["chain_intact"] is True
    assert record["broken_at"] is None
    assert "altered or removed in place" in record["proves"]


def test_a_tampered_log_is_reported_as_broken_rather_than_clean(client, paid):
    """The whole point. A quiet 'looks fine' over a rewritten log is the bug."""
    _, seq = paid
    entries = gateway.state.audit.entries()
    victim = entries[seq]
    object.__setattr__(victim, "amount_paise", 1)

    record = client.get(f"/incident/{seq}").json()["record"]

    assert record["chain_intact"] is False
    assert record["broken_at"]
    assert record["proves"] == "nothing - the chain is broken"


def test_an_unreviewed_payment_does_not_read_as_an_approved_one(client, paid):
    """No monitor was configured in this test, and the report has to say so."""
    _, seq = paid
    judgement = client.get(f"/incident/{seq}").json()["judgement"]

    assert judgement["verdict"] in ("unconfigured", "skipped")
    assert "NOT" in judgement["means"] or "switched off" in judgement["means"]


def test_every_recorded_verdict_is_explained_in_words(client, paid):
    """A verdict nobody can interpret is not evidence."""
    _, seq = paid
    judgement = client.get(f"/incident/{seq}").json()["judgement"]

    assert judgement["means"]
    assert judgement["means"] != judgement["verdict"]


def test_the_view_changes_nothing(client, paid):
    """Read-only. An investigation tool that can move money is a second rail."""
    mandate, seq = paid
    before = client.get(f"/mandates/{mandate['mandate_id']}").json()
    head_before = gateway.state.audit.head

    client.get(f"/incident/{seq}")
    client.get(f"/incident/{seq}")

    after = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert after["committed_paise"] == before["committed_paise"]
    assert gateway.state.audit.head == head_before
