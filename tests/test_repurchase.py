"""The same cart, twice.

Two failures live here and only one of them is a hashing problem.

The fingerprint once covered the cart alone, so the same basket at a different
price hashed identical and the second call was handed back the first receipt -
a price change disappearing in silence, with the replay branch never comparing
amounts. Putting the amount in the key closes that.

What the amount cannot close is an honest repeat: same cart, same price, inside
the TTL. That is byte-for-byte a retry, and nothing in the request separates the
two. So the caller has to say which it meant - and the whole difficulty is that
it must not be able to say so in a way that spends money on its own.

Every test below asserts the ledger separately from the audit, because the
failure being guarded against is precisely a clean record over a wrong transfer.
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import gateway
from pocketchange.audit import Decision
from pocketchange.policy import RUPEE

CART = {"STA-A4-5": 3}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("RAZORPAY_KEY_SECRET", raising=False)
    gateway.state = gateway.State()
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


@pytest.fixture
def mandate(client):
    r = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE,
        "purpose": "restock the stationery cupboard",
        "ttl_seconds": 3600,
    })
    assert r.status_code == 200
    return r.json()


def pay(client, tok, amount, cart=CART, *, repurchase=None):
    body = {"amount_paise": amount, "cart": cart, "context": "restocking"}
    if repurchase is not None:
        body["repurchase"] = repurchase
    return client.post("/pay", headers={"X-AIP-Token": tok}, json=body)


def committed(client, mandate_id):
    return client.get(f"/mandates/{mandate_id}").json()["committed_paise"]


# --- what the amount in the key fixes ---------------------------------------


def test_the_same_cart_at_a_different_price_is_a_separate_purchase(client, mandate):
    """Asserted on the ledger, not the response - a response lies as easily."""
    first = pay(client, mandate["token"], 300 * RUPEE).json()
    second = pay(client, mandate["token"], 450 * RUPEE).json()

    assert second["replayed"] is False
    assert second["order_id"] != first["order_id"]
    assert committed(client, mandate["mandate_id"]) == 750 * RUPEE


def test_the_same_cart_at_the_same_price_still_replays(client, mandate):
    """The default path is untouched: a retry gets the original receipt."""
    first = pay(client, mandate["token"], 300 * RUPEE).json()
    again = pay(client, mandate["token"], 300 * RUPEE).json()

    assert again["replayed"] is True
    assert again["order_id"] == first["order_id"]
    assert committed(client, mandate["mandate_id"]) == 300 * RUPEE


# --- what the amount cannot fix ----------------------------------------------


def test_asking_to_repurchase_settles_nothing_by_itself(client, mandate):
    """The security property, and the reason an agent may set this flag.

    `derive_key` refuses a caller-chosen idempotency KEY because an agent could
    defeat replay protection by picking a fresh one. A caller-chosen FLAG is a
    different thing, because its only reachable effect is to demand MORE
    authorisation. An agent that sets it on every call earns itself a person
    reading every payment, and nothing else.
    """
    pay(client, mandate["token"], 300 * RUPEE)

    r = pay(client, mandate["token"], 300 * RUPEE, repurchase=True)
    assert r.status_code == 202
    assert r.json()["detail"]["occurrence"] == 1
    assert committed(client, mandate["mandate_id"]) == 300 * RUPEE


def test_an_approved_repurchase_charges_exactly_once(client, mandate):
    pay(client, mandate["token"], 300 * RUPEE)
    pending = pay(client, mandate["token"], 300 * RUPEE,
                  repurchase=True).json()["detail"]

    done = client.post(f"/approvals/{pending['approval_id']}",
                       json={"decision": "approve", "by": "somay"})

    assert done.status_code == 200
    assert committed(client, mandate["mandate_id"]) == 600 * RUPEE


def test_a_refused_repurchase_leaves_the_first_payment_standing(client, mandate):
    """Denial frees the repeat's hold without disturbing the original."""
    first = pay(client, mandate["token"], 300 * RUPEE).json()
    pending = pay(client, mandate["token"], 300 * RUPEE,
                  repurchase=True).json()["detail"]

    client.post(f"/approvals/{pending['approval_id']}",
                json={"decision": "deny", "by": "somay", "note": "already have it"})

    assert committed(client, mandate["mandate_id"]) == 300 * RUPEE
    again = pay(client, mandate["token"], 300 * RUPEE).json()
    assert again["replayed"] is True
    assert again["order_id"] == first["order_id"]


def test_the_flag_on_a_first_payment_does_nothing(client, mandate):
    """There is no prior payment to be confused with, so there is nothing to ask."""
    r = pay(client, mandate["token"], 300 * RUPEE, repurchase=True)

    assert r.status_code == 200
    assert r.json()["replayed"] is False
    assert committed(client, mandate["mandate_id"]) == 300 * RUPEE


def test_a_repeat_is_charged_against_the_cap_like_any_other_payment(client):
    """Having bought something once is not authority to buy it again for free."""
    small = client.post("/mandates", json={
        "budget_paise": 400 * RUPEE, "purpose": "one ream only", "ttl_seconds": 3600,
    }).json()
    pay(client, small["token"], 300 * RUPEE)

    r = pay(client, small["token"], 300 * RUPEE, repurchase=True)

    assert r.status_code == 402
    assert committed(client, small["mandate_id"]) == 300 * RUPEE


# --- the record --------------------------------------------------------------


def test_an_approved_repeat_is_not_recorded_as_a_monitor_escalation(client, mandate):
    """It was held because it was a repeat, not because anything judged it.

    Writing `monitor: escalate` across both would put a verdict in the audit
    that no monitor ever gave - the same class of defect as recording an
    unconfigured monitor as an approval.
    """
    pay(client, mandate["token"], 300 * RUPEE)
    pending = pay(client, mandate["token"], 300 * RUPEE,
                  repurchase=True).json()["detail"]
    client.post(f"/approvals/{pending['approval_id']}",
                json={"decision": "approve", "by": "somay"})

    paid = [e for e in gateway.state.audit.entries()
            if e.tool == "pay" and e.decision is Decision.ALLOWED][-1]
    assert paid.detail["held_by"] == "repurchase"
    assert paid.detail["monitor"] == "not-consulted"


def test_the_occurrence_number_comes_from_us_and_not_from_the_caller(client, mandate):
    """Successive repeats number themselves, and the request never says so.

    An agent supplying its own occurrence would be choosing its own idempotency
    key, which is the thing the whole module exists to refuse.
    """
    pay(client, mandate["token"], 300 * RUPEE)

    first = pay(client, mandate["token"], 300 * RUPEE,
                repurchase=True).json()["detail"]
    client.post(f"/approvals/{first['approval_id']}",
                json={"decision": "approve", "by": "somay"})
    second = pay(client, mandate["token"], 300 * RUPEE,
                 repurchase=True).json()["detail"]

    assert first["occurrence"] == 1
    assert second["occurrence"] == 2
