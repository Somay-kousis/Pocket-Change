"""The enforcement point, end to end.

No credentials are loaded here, so razorpay_client.from_env() returns FakeRail
and nothing touches the network. That is deliberate: the check order must be
testable without a payment account.
"""

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import gateway
from pocketchange.audit import Decision
from pocketchange.policy import RUPEE


@pytest.fixture
def client(monkeypatch):
    """A fresh gateway per test - new root key, empty ledger, empty audit."""
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("RAZORPAY_KEY_SECRET", raising=False)
    gateway.state = gateway.State()
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


@pytest.fixture
def mandate(client):
    r = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE,
        "purpose": "weekly grocery run",
        "ttl_seconds": 3600,
    })
    assert r.status_code == 200
    return r.json()


def _pay(client, tok, amount, cart, context="buying the cart the shopper assembled"):
    return client.post(
        "/pay",
        headers={"X-AIP-Token": tok},
        json={"amount_paise": amount, "cart": cart, "context": context},
    )


def test_health_reports_fake_rail(client):
    assert client.get("/healthz").json()["rail"] == "fake"


def test_happy_path(client, mandate):
    r = _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4})
    assert r.status_code == 200
    body = r.json()
    assert body["order_id"].startswith("order_fake_")
    assert body["remaining_paise"] == 240_400 * RUPEE
    assert body["replayed"] is False


def test_cumulative_budget_exhausted(client, mandate):
    """The headline denial, through the full stack.

    Both payments carry the same valid token. AIP as specified allows both.
    """
    assert _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4}).status_code == 200
    r = _pay(client, mandate["token"], 359_600 * RUPEE, {"dal": 2})
    assert r.status_code == 402
    detail = r.json()["detail"]
    assert detail["denied"] == "cumulative budget exhausted"


def test_replay_returns_original_order(client, mandate):
    """Same cart twice: one charge, and the second says so."""
    first = _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4}).json()
    second = _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4}).json()

    assert second["replayed"] is True
    assert second["order_id"] == first["order_id"]
    assert len(gateway.state.rail.orders) == 1


def test_cart_order_does_not_defeat_replay(client, mandate):
    """Reordering the cart keys must not look like a new purchase."""
    first = _pay(client, mandate["token"], 200_000 * RUPEE, {"rice": 4, "dal": 2}).json()
    second = _pay(client, mandate["token"], 200_000 * RUPEE, {"dal": 2, "rice": 4}).json()
    assert second["order_id"] == first["order_id"]


def test_shopper_token_cannot_pay(client, mandate):
    """The injection defence at the HTTP boundary."""
    d = client.post("/delegate", json={
        "token": mandate["token"],
        "tools": ["search", "cart"],
        "budget_paise": 600_000 * RUPEE,
        "context": "reading listings",
    }).json()

    r = _pay(client, d["token"], 40_000 * RUPEE, {"rice": 1})
    assert r.status_code == 403


def test_forged_token_rejected(client, mandate):
    other = gateway.State()
    stolen = other.principal
    import datetime as dt

    from pocketchange import token as tk
    rogue = tk.mint(
        stolen, budget_paise=4_000_000 * RUPEE, max_depth=3,
        expires=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1),
    )
    r = _pay(client, tk.serialize(rogue), 40_000 * RUPEE, {"rice": 1})
    assert r.status_code == 401


def test_whitespace_context_rejected(client, mandate):
    r = _pay(client, mandate["token"], 40_000 * RUPEE, {"rice": 1}, context="   ")
    assert r.status_code == 400


def test_missing_token_rejected(client):
    r = client.post("/pay", json={
        "amount_paise": 100, "cart": {"x": 1}, "context": "no token attached"
    })
    assert r.status_code == 401


def test_http_binding_works(client, mandate):
    r = client.post(
        "/pay",
        headers={"Authorization": f"AIP {mandate['token']}"},
        json={"amount_paise": 40_000 * RUPEE, "cart": {"rice": 1}, "context": "http binding"},
    )
    assert r.status_code == 200


def test_a2a_binding_works(client, mandate):
    r = client.post("/pay", json={
        "amount_paise": 40_000 * RUPEE, "cart": {"rice": 1},
        "context": "a2a binding", "aip_token": mandate["token"],
    })
    assert r.status_code == 200


def test_audit_records_denials_and_stays_intact(client, mandate):
    _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4})
    _pay(client, mandate["token"], 359_600 * RUPEE, {"dal": 2})  # denied

    trail = client.get("/audit").json()
    assert trail["intact"] is True
    decisions = [e["decision"] for e in trail["entries"]]
    assert "allowed" in decisions and "denied" in decisions

    denial = next(e for e in trail["entries"] if e["decision"] == "denied")
    assert denial["reason"] == "cumulative budget exhausted"
    assert denial["detail"]["available"] == 240_400 * RUPEE


def test_ledger_endpoint_reflects_spend(client, mandate):
    _pay(client, mandate["token"], 359_600 * RUPEE, {"rice": 4})
    s = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert s["committed_paise"] == 359_600 * RUPEE
    assert s["available_paise"] == 240_400 * RUPEE


# --- the second layer ------------------------------------------------------


def test_monitor_escalation_suspends_and_holds_the_budget(client, mandate):
    """Escalation pauses a payment; it does not refuse it.

    The reservation is HELD. Releasing it would let other spending consume the
    budget this payment is waiting on, so a human saying yes ten minutes later
    could fail for reasons unrelated to their decision.
    """
    from pocketchange.monitor import ScriptedMonitor, Verdict

    gateway.state.monitor = ScriptedMonitor(
        Verdict.ESCALATE, "40kg of rice is not a household order"
    )

    r = _pay(client, mandate["token"], 359_600 * RUPEE, {"LAP-STD-1": 40})
    assert r.status_code == 202
    body = r.json()["detail"]
    assert body["status"] == "pending_approval"
    assert body["approval_id"].startswith("ap_")

    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert state["reserved_paise"] == 359_600 * RUPEE
    assert state["committed_paise"] == 0


def test_monitor_evidence_is_trusted_and_the_claim_is_labelled(client, mandate):
    """Judgement rests on observed facts; the agent's account is named untrusted."""
    from pocketchange.monitor import ScriptedMonitor, Verdict

    spy = ScriptedMonitor(Verdict.ALLOW, "fine")
    gateway.state.monitor = spy

    _pay(client, mandate["token"], 263_200 * RUPEE, {"LAP-STD-1": 4},
         context="buying the rice and dal the household asked for")

    seen = spy.seen[0]
    assert seen.intent == "weekly grocery run"
    assert seen.agent_claim == "buying the rice and dal the household asked for"
    assert seen.cap_paise == 600_000 * RUPEE


def test_allowed_payment_records_monitor_verdict(client, mandate):
    """The audit trail says what the monitor thought, not just what happened."""
    from pocketchange import gateway
    from pocketchange.monitor import ScriptedMonitor, Verdict

    gateway.state.monitor = ScriptedMonitor(Verdict.ALLOW, "looks ordinary")
    _pay(client, mandate["token"], 263_200 * RUPEE, {"LAP-STD-1": 4})
    entry = [e for e in client.get("/audit").json()["entries"] if e["tool"] == "pay"][0]
    assert entry["detail"]["monitor"] == "allow"
    assert entry["detail"]["monitor_ran"] is True


def test_an_unconfigured_monitor_is_recorded_as_absent_not_as_approval(client, mandate):
    """The dishonesty this exists to stop.

    With no key, `monitor.from_env` returns a stand-in that answers ALLOW to
    everything. Recording that as `monitor: allow` put a verdict in the audit
    that nothing had formed - a run with no second layer read exactly like one
    that passed it, under a console checkbox saying the monitor was on.
    """
    from pocketchange import gateway
    from pocketchange.monitor import from_env

    gateway.state.monitor = from_env()          # offline: the stand-in
    _pay(client, mandate["token"], 263_200 * RUPEE, {"LAP-STD-1": 4})
    entry = [e for e in client.get("/audit").json()["entries"] if e["tool"] == "pay"][0]

    assert entry["detail"]["monitor"] == "unconfigured"
    assert entry["detail"]["monitor_ran"] is False
    assert "no monitor configured" in entry["detail"]["monitor_reason"]
    # And it must stay distinct from a monitor someone deliberately switched off.
    assert entry["detail"]["monitor"] != "skipped"


# --- depth is derived, not claimed ------------------------------------------
#
# Until the funnel work, Operation.depth came from the request body: the agent
# being depth-limited filled in its own depth. These tests pin the fix.


def _delegate(client, tok, *, budget, tools=("pay",), depth=None, to=None):
    body = {
        "token": tok,
        "tools": list(tools),
        "budget_paise": budget,
        "context": "handing a narrower slice of authority onward",
    }
    if depth is not None:
        body["depth"] = depth
    if to is not None:
        body["to"] = to
    return client.post("/delegate", json=body)


def test_depth_of_counts_blocks_not_claims(client):
    r = client.post("/mandates", json={
        "budget_paise": 100_000 * RUPEE, "purpose": "root", "max_depth": 3,
    })
    tok = r.json()["token"]
    from pocketchange import token as tk

    parsed = tk.deserialize(tok, gateway.state.root_public_key)
    assert tk.depth_of(parsed) == 0

    for expected in (1, 2, 3):
        tok = _delegate(client, tok, budget=10_000 * RUPEE,
                        tools=("delegate", "pay")).json()["token"]
        parsed = tk.deserialize(tok, gateway.state.root_public_key)
        assert tk.depth_of(parsed) == expected


def test_over_deep_token_is_refused_however_it_reports_itself(client):
    """The bug this closes: claim depth 0 from deep in the chain and walk past
    the max_depth check. The claim is now ignored."""
    tok = client.post("/mandates", json={
        "budget_paise": 100_000 * RUPEE, "purpose": "root", "max_depth": 2,
    }).json()["token"]

    # Two delegations are allowed: depths 1 and 2.
    for _ in range(2):
        r = _delegate(client, tok, budget=10_000 * RUPEE, tools=("delegate", "pay"))
        assert r.status_code == 200, r.text
        tok = r.json()["token"]

    # A third would sit at depth 3. Lying about it must not help.
    for claimed in (None, 0, 1):
        r = _delegate(client, tok, budget=1_000 * RUPEE, depth=claimed)
        assert r.status_code == 403, f"claimed={claimed} got through: {r.text}"


def test_a_lie_about_depth_is_recorded(client, mandate):
    """Ignoring the field silently would throw away the signal. It is evidence."""
    before = len(gateway.state.audit)
    r = _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1})
    assert r.status_code == 200

    # Root token is depth 0; claim to be somewhere else entirely.
    client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 500 * RUPEE, "cart": {"BREAD-1": 1},
        "context": "second line of the same run", "depth": 7,
    })
    lies = [e for e in list(gateway.state.audit.entries())[before:]
            if e.reason == "claimed depth does not match the token chain"]
    assert len(lies) == 1
    assert lies[0].detail == {"claimed_depth": 7, "derived_depth": 0}


def test_mandate_may_now_reach_depth_eight(client):
    assert client.post("/mandates", json={
        "budget_paise": 100 * RUPEE, "purpose": "deep funnel", "max_depth": 8,
    }).status_code == 200
    assert client.post("/mandates", json={
        "budget_paise": 100 * RUPEE, "purpose": "too deep", "max_depth": 9,
    }).status_code == 422


# --- the live stream --------------------------------------------------------


def test_events_endpoint_serves_the_buffer(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=100))
    ev.bus.emit("root", ev.SPAWNED, depth=0, description="equip the office")
    ev.bus.emit("root.1", ev.GRANTED, parent_id="root", depth=1,
                budget_paise=1000, tools=["pay"])

    body = client.get("/events").json()
    assert body["total"] == 2
    assert [e["kind"] for e in body["events"]] == ["spawned", "granted"]
    assert body["events"][1]["parent_id"] == "root"
    assert body["dropped"] == 0


def test_stream_encodes_events_as_sse(monkeypatch):
    """Driven through the generator rather than TestClient: an SSE endpoint is
    endless by design, and a test client that waits for the last byte waits
    forever."""
    import json as _json
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=100))
    ev.bus.emit("root", ev.SPAWNED, depth=0, description="equip the office")

    response = gateway.stream()
    assert response.media_type == "text/event-stream"
    assert response.headers["cache-control"] == "no-cache"

    # Starlette wraps the sync generator in an async one.
    import asyncio

    chunks = response.body_iterator

    def take():
        return asyncio.run(chunks.__anext__())

    assert take() == ": connected\n\n"

    first = take()
    head, _, payload = first.partition("\n")
    assert head == "event: spawned"
    data = _json.loads(payload[len("data: "):])
    assert data["node_id"] == "root"
    assert data["detail"]["description"] == "equip the office"


def test_a_subscriber_that_stops_reading_cannot_stall_the_run():
    """The reason the bus is allowed to be lossy at all."""
    from pocketchange import events as ev

    bus = ev.EventBus(queue_size=4)
    bus.subscribe()                       # nobody ever reads it
    for i in range(50):
        bus.emit(f"root.{i}", ev.SPAWNED, depth=1)
    assert bus.dropped == 46
    assert len(bus.history()) == 50       # history is unaffected


def test_the_stream_is_not_the_audit_log(client, mandate):
    """Two records with different jobs. Losing a stream event is survivable;
    losing an audit entry is not, so payments write to the audit log and the
    funnel writes to the bus, and neither is derived from the other."""
    before = len(gateway.state.audit)
    _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1})
    assert len(gateway.state.audit) > before


def test_a_funnel_in_another_process_can_publish(client, monkeypatch):
    """Without this the funnel runs in the agent process, the bus is in the
    gateway process, and `pocketchange watch` shows an empty screen."""
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=100))
    r = client.post("/events", json={
        "node_id": "root.1", "parent_id": "root", "depth": 1,
        "kind": "granted", "detail": {"budget_paise": 1000, "tools": ["pay"]},
    })
    assert r.status_code == 200
    assert client.get("/events").json()["total"] == 1


def test_an_unknown_event_kind_is_refused(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=100))
    r = client.post("/events", json={"node_id": "root", "kind": "transfer_all_funds"})
    assert r.status_code == 400
    assert client.get("/events").json()["total"] == 0


def test_remote_bus_never_fails_a_run_when_the_gateway_is_gone():
    """A progress line that could fail a payment would be worse than no line."""
    from pocketchange import events as ev

    bus = ev.RemoteBus("http://127.0.0.1:1", timeout=0.05)   # nothing listening
    event = bus.emit("root", ev.SPAWNED, depth=0, description="equip the office")
    assert event.node_id == "root"
    assert bus.failures == 1
    assert len(bus.history()) == 1      # still inspectable locally


# --- POST /runs -------------------------------------------------------------
#
# The console could not previously start a run, so its centrepiece had to be a
# simulation. These pin the endpoint that replaced it.


def _wait_for(predicate, tries=60, pause=0.05):
    import time

    for _ in range(tries):
        if predicate():
            return True
        time.sleep(pause)
    return False


def test_a_run_mints_a_mandate_and_builds_a_real_tree(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=10_000))
    r = client.post("/runs", json={
        "task": "Kit out the new engineering office",
        "budget_paise": 200_000 * RUPEE, "fan_out": 3,
        "floor_paise": 25_000 * RUPEE,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["task"] == "Kit out the new engineering office"
    assert "deterministic" in body["decomposer"]

    assert _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))
    _wait_for(lambda: len({e.node_id for e in ev.bus.history()}) >= 13)

    ledger = client.get(f"/mandates/{body['mandate_id']}").json()
    assert ledger["cap_paise"] == 200_000 * RUPEE
    assert 0 < ledger["committed_paise"] <= 200_000 * RUPEE


def test_a_run_cannot_outspend_the_ceiling_it_was_given(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=10_000))
    cap = 90_000 * RUPEE
    body = client.post("/runs", json={
        "task": "Quarterly consumables restock", "budget_paise": cap,
        "fan_out": 3, "floor_paise": 11_000 * RUPEE,
    }).json()

    _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))
    _wait_for(lambda: client.get(f"/mandates/{body['mandate_id']}").json()["available_paise"] < cap)

    ledger = client.get(f"/mandates/{body['mandate_id']}").json()
    assert ledger["committed_paise"] + ledger["reserved_paise"] <= cap


def test_a_leaf_below_the_floor_is_granted_pay_and_not_delegate(client, monkeypatch):
    """The floor is what makes a leaf a leaf. Set too low relative to the budget,
    every node stays 'big enough to split' and carries delegate it never uses."""
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=10_000))
    client.post("/runs", json={
        "task": "Refresh design team hardware", "budget_paise": 200_000 * RUPEE,
        "fan_out": 3, "floor_paise": 25_000 * RUPEE,
    })
    assert _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))

    grants = {e.node_id: e.detail["tools"]
              for e in ev.bus.history() if e.kind == ev.GRANTED}
    leaves = {k: v for k, v in grants.items() if k.count(".") == 2 and "search" not in k}
    assert leaves, grants
    # A web-sourced leaf also holds `search`, which is correct - it must read
    # supplier pages. The property is that no leaf holds `delegate`.
    assert all("delegate" not in v for v in leaves.values()), leaves
    assert all("pay" in v for v in leaves.values()), leaves

    lookers = {k: v for k, v in grants.items() if k.endswith(".search")}
    assert all(v == ["search"] for v in lookers.values())


def test_a_run_refuses_a_budget_beyond_the_endpoint_limit(client):
    assert client.post("/runs", json={
        "task": "buy everything", "budget_paise": 10_000_000_000,
    }).status_code == 422


# --- what the console can now show ------------------------------------------


def test_audit_verify_confirms_an_intact_chain(client, mandate):
    _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1})
    body = client.get("/audit/verify").json()
    assert body["ok"] is True
    assert body["entries"] == len(gateway.state.audit)
    assert body["head"] == gateway.state.audit.head
    # It must not overclaim: an intact chain is not proof of an unrewritten log.
    assert "external anchor" in body["proves"]


def test_audit_verify_reports_a_broken_chain(client, mandate):
    _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1})
    entries = gateway.state.audit._entries
    object.__setattr__(entries[-1], "reason", "quietly rewritten")

    body = client.get("/audit/verify").json()
    assert body["ok"] is False
    assert body["broken_at"]
    assert body["proves"] == "nothing - the chain is broken"


def test_replay_returns_the_same_order_and_does_not_charge_twice(client, monkeypatch):
    from pocketchange import events as ev
    from pocketchange.monitor import ScriptedMonitor, Verdict

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=10_000))
    gateway.state.monitor = ScriptedMonitor(verdict=Verdict.ALLOW)
    body = client.post("/runs", json={
        "task": "Quarterly consumables restock", "budget_paise": 90_000 * RUPEE,
        "fan_out": 3, "floor_paise": 11_000 * RUPEE, "decomposer": "departmental",
    }).json()
    assert _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))

    paid = [e for e in gateway.state.audit.entries()
            if e.tool == "pay" and e.decision is Decision.ALLOWED]
    assert paid
    out = client.post(f"/replay/{paid[0].seq}").json()

    assert out["same_order"] is True
    assert out["second"]["replayed"] is True
    assert out["charged_twice"] is False
    assert out["committed_after_paise"] == out["committed_before_paise"]
    assert body["mandate_id"]


def test_replay_of_an_unknown_entry_is_a_404(client):
    assert client.post("/replay/99999").status_code == 404


def test_a_run_reports_which_decomposer_ran(client, monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    body = client.post("/runs", json={
        "task": "anything", "budget_paise": 50_000 * RUPEE, "decomposer": "auto",
    }).json()
    # With no key, auto must fall back and SAY so - a console that implied a
    # model was involved would be claiming reasoning that never happened.
    assert body["decomposer"].startswith("departmental")

    r = client.post("/runs", json={
        "task": "anything", "budget_paise": 50_000 * RUPEE, "decomposer": "model",
    })
    assert r.status_code == 400


def test_the_monitor_cannot_be_switched_off_by_an_external_caller(client, mandate):
    """The one control an untrusted agent must never hold."""
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 500 * RUPEE, "cart": {"MILK-1L": 1},
        "context": "buying milk", "monitor": False,
    })
    assert r.status_code == 422          # extra="forbid" rejects the field

    assert gateway.MONITOR_ON.get() is True


def test_skipping_the_monitor_is_recorded_as_skipped_not_allowed(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=10_000))
    client.post("/runs", json={
        "task": "restock", "budget_paise": 60_000 * RUPEE, "fan_out": 3,
        "floor_paise": 11_000 * RUPEE, "decomposer": "departmental",
        "monitor": False,
    })
    assert _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))

    paid = [e for e in gateway.state.audit.entries()
            if e.tool == "pay" and e.decision is Decision.ALLOWED]
    assert paid
    assert paid[0].detail["monitor"] == "skipped"
    assert paid[0].detail["monitor_ran"] is False


def test_audit_entries_name_their_mandate(client, mandate):
    """Without this the console cannot find the ledger for a run, and the
    ceiling - the headline number - renders as an em dash."""
    _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1})
    entries = client.get("/audit").json()["entries"]
    assert entries
    assert all(e["mandate_id"] for e in entries)
    opened = next(e for e in entries if e["tool"] == "mandate")
    assert opened["mandate_id"] == mandate["mandate_id"]
    assert client.get(f"/mandates/{opened['mandate_id']}").status_code == 200


def test_a_stalled_run_tells_the_console_rather_than_spinning(client, monkeypatch):
    """drive() catches exceptions. It does not catch hangs: a decompose call
    that never returns leaves the tree simply not growing, with no terminal
    event and a console that cannot tell thinking from dead."""
    import threading
    from pocketchange import events as ev, funnel as fn

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=1000))
    monkeypatch.setattr(gateway, "RUN_DEADLINE_SECONDS", 0.3)

    blocked = threading.Event()
    monkeypatch.setattr(
        gateway, "_departmental",
        lambda fan_out: (lambda node: blocked.wait(20) or []))

    try:
        client.post("/runs", json={
            "task": "something that hangs", "budget_paise": 50_000 * RUPEE,
            "decomposer": "departmental",
        })
        assert _wait_for(
            lambda: any(e.kind == ev.BOUND_HIT and e.detail.get("fault")
                        and "stalled" in e.detail.get("reason", "")
                        for e in ev.bus.history()),
            tries=40, pause=0.1)
    finally:
        blocked.set()


def test_a_run_that_finishes_promptly_raises_no_stall(client, monkeypatch):
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=1000))
    monkeypatch.setattr(gateway, "RUN_DEADLINE_SECONDS", 5.0)
    client.post("/runs", json={
        "task": "restock", "budget_paise": 40_000 * RUPEE, "fan_out": 3,
        "floor_paise": 11_000 * RUPEE, "decomposer": "departmental", "monitor": False,
    })
    assert _wait_for(lambda: any(e.kind == ev.SETTLED for e in ev.bus.history()))
    import time
    time.sleep(0.4)
    assert not any("stalled" in (e.detail.get("reason") or "") for e in ev.bus.history())


def test_the_rail_cap_is_overridable_and_refuses_an_unpayable_leaf(client, monkeypatch):
    """Documented in the README as POCKETCHANGE_MAX_LEAF_PAISE, so it has to
    exist. The realistic path to an oversized leaf is a task that does not
    divide: the root narrows to a sole payer holding the whole budget."""
    from pocketchange import events as ev

    monkeypatch.setattr(ev, "bus", ev.EventBus(history=1000))
    monkeypatch.setenv("POCKETCHANGE_MAX_LEAF_PAISE", str(20_000 * RUPEE))
    monkeypatch.setattr(gateway, "_departmental", lambda fan_out: (lambda node: []))

    client.post("/runs", json={
        "task": "one indivisible purchase", "budget_paise": 90_000 * RUPEE,
        "decomposer": "departmental", "monitor": False,
    })
    assert _wait_for(lambda: any(
        e.kind == ev.BOUND_HIT and e.detail.get("limit_paise") for e in ev.bus.history()))

    hit = next(e for e in ev.bus.history() if e.detail.get("limit_paise"))
    assert hit.detail["fault"] is True
    assert hit.detail["limit_paise"] == 20_000 * RUPEE
    assert hit.detail["amount_paise"] == 90_000 * RUPEE
    # And nothing was ever sent to the rail.
    assert not [e for e in gateway.state.audit.entries() if e.tool == "pay"]


def test_a_floor_above_the_rail_cap_is_refused_before_any_payment(client, monkeypatch):
    monkeypatch.setenv("POCKETCHANGE_MAX_LEAF_PAISE", str(5_000 * RUPEE))
    r = client.post("/runs", json={
        "task": "anything", "budget_paise": 90_000 * RUPEE,
        "floor_paise": 50_000 * RUPEE, "decomposer": "departmental",
    })
    assert r.status_code == 400
    assert "rail cap" in str(r.json()["detail"])


# --- who we have actually paid ---------------------------------------------


def test_a_payment_records_the_counterparty_only_once_it_clears(client, mandate):
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 500 * RUPEE, "cart": {"MILK-1L": 1},
        "context": "buying milk", "counterparty": "meridian-systems",
    })
    assert r.status_code == 200
    row = gateway.state.counterparties.lookup("meridian-systems")
    assert row.orders == 1 and row.total_paise == 500 * RUPEE

    body = client.get("/counterparties").json()
    assert body["count"] == 1
    assert body["counterparties"][0]["id"] == "meridian-systems"


def test_a_refused_payment_counts_as_trouble_not_as_custom(client, mandate):
    """A refusal is not a dealing - orders stays at zero - but it is absolutely
    something to remember about them. A party we tried and failed to pay has a
    worse record than one we have never heard of, not an identical one."""
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 900_000 * RUPEE, "cart": {"LAP-PRO-1": 99},
        "context": "far beyond the ceiling", "counterparty": "bestdeals-procurement",
    })
    assert r.status_code == 403

    row = gateway.state.counterparties.lookup("bestdeals-procurement")
    assert row is not None
    assert row.orders == 0 and row.total_paise == 0     # no custom
    assert row.refused == 1 and row.trouble == 1        # but a record
    assert "CONCERNS" in row.describe()
    assert "never paid" in row.describe()


def test_the_monitor_is_told_our_record_not_the_sellers(client, mandate, monkeypatch):
    """The whole point. `seller_reputation` reports what a seller says about
    itself; this reports what we have actually done."""
    from pocketchange.monitor import ScriptedMonitor, Verdict

    seen = ScriptedMonitor(verdict=Verdict.ALLOW)
    gateway.state.monitor = seen

    # Distinct carts, because identical ones derive the same idempotency key and
    # the second would be replayed rather than judged again.
    for n in (1, 2, 3):
        client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
            "amount_paise": 100 * RUPEE, "cart": {"STA-A4-5": n},
            "context": "paper", "counterparty": "northgate-supply",
        })

    first, second, third = seen.seen[0], seen.seen[1], seen.seen[2]
    assert first.counterparty == "northgate-supply"
    assert first.counterparty_history == "never paid before"      # no row yet
    assert second.counterparty_history == "paid once before, 100 rupees"
    assert "paid 2 times" in third.counterparty_history


def test_an_unnamed_counterparty_says_so_rather_than_guessing(client, mandate):
    from pocketchange.monitor import ScriptedMonitor, Verdict
    from pocketchange import counterparties as cp

    seen = ScriptedMonitor(verdict=Verdict.ALLOW)
    gateway.state.monitor = seen
    client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 100 * RUPEE, "cart": {"STA-A4-5": 1}, "context": "paper",
    })
    assert seen.seen[0].counterparty == ""
    assert seen.seen[0].counterparty_history == cp.UNKNOWN


def test_an_escalated_payment_still_records_when_a_human_releases_it(client, mandate):
    """The record must not depend on whether a person happened to look."""
    from pocketchange.monitor import ScriptedMonitor, Verdict

    gateway.state.monitor = ScriptedMonitor(verdict=Verdict.ESCALATE, reason="new supplier")
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 700 * RUPEE, "cart": {"CHR-ERG-1": 1},
        "context": "a chair", "counterparty": "vector-distribution",
    })
    assert r.status_code == 202
    approval_id = r.json()["detail"]["approval_id"]

    held = gateway.state.counterparties.lookup("vector-distribution")
    assert held.orders == 0 and held.escalated == 1     # held, not yet paid

    gateway.state.monitor = ScriptedMonitor(verdict=Verdict.ALLOW)
    ok = client.post(f"/approvals/{approval_id}", json={"decision": "approve", "by": "human"})
    assert ok.status_code == 200
    row = gateway.state.counterparties.lookup("vector-distribution")
    assert row.orders == 1
    # And the escalation is still on the record. A payment a person had to be
    # asked about does not become an ordinary one because they said yes.
    assert row.escalated == 1


def test_the_standing_endpoint_separates_running_from_waiting(client, monkeypatch):
    """Drafting a policy asks a model to turn a sentence into reorder rules, so
    the model is scripted here - the subject is what the endpoint does with the
    result, not what the model says."""
    import agent.nodes as nodes
    from pocketchange import memory

    def scripted(*, instruction, department, period, budget_paise):
        return memory.new_order(
            instruction=instruction, department=department, period=period,
            period_budget_paise=budget_paise,
            rules=(memory.ReorderRule("STA-A4-5", 5, 20),),
        )

    monkeypatch.setattr(nodes, "establish", scripted)

    r = client.post("/standing", json={
        "instruction": "keep the stationery cupboard stocked with A4 paper",
        "department": "operations", "period": "month",
        "budget_paise": 60_000 * RUPEE,
    })
    assert r.status_code == 200, r.text

    # Default is what the tick loop reads: only what a person authorised.
    assert client.get("/standing").json()["orders"] == []
    waiting = client.get("/standing?include_pending=true").json()["orders"]
    assert len(waiting) == 1 and waiting[0]["approved"] is False

    # And it is queued for a person, as a policy rather than a payment.
    pending = client.get("/approvals").json()["pending"]
    assert any(p["kind"] == "policy" for p in pending)


# --- the demo gate ----------------------------------------------------------
#
# A public URL with no auth is a free tier waiting to be drained. This is not
# authentication - the token ships inside a public page - it is a brake.


def test_unset_gates_nothing(client, mandate):
    """Local development and this suite must behave exactly as before."""
    assert gateway.DEMO_TOKEN == ""
    assert _pay(client, mandate["token"], 500 * RUPEE, {"MILK-1L": 1}).status_code == 200


def test_with_a_token_every_write_is_refused_without_it(client, monkeypatch):
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")

    writes = [
        ("/runs", {"task": "x", "budget_paise": 50_000 * RUPEE}),
        ("/mandates", {"budget_paise": 1000, "purpose": "x"}),
        ("/delegate", {"token": "x", "tools": ["pay"], "budget_paise": 1, "context": "x"}),
        ("/events", {"node_id": "root", "kind": "spawned"}),
        ("/approvals/ap_x", {"decision": "approve"}),
        ("/replay/1", None),
        ("/agents", {"name": "x", "version": "1", "department": "d", "owner": "o",
                     "identity": "aip:web:x/y", "capabilities": ["pay"],
                     "max_budget_paise": 1}),
        ("/standing", {"instruction": "x", "department": "d", "budget_paise": 1}),
    ]
    for path, body in writes:
        r = client.post(path, json=body) if body else client.post(path)
        assert r.status_code == 401, f"{path} was not gated"
        assert "demo token" in str(r.json()["detail"])


def test_reads_stay_open_so_a_judge_can_look_around(client, monkeypatch):
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")
    for path in ("/healthz", "/audit", "/audit/verify", "/counterparties",
                 "/agents", "/standing", "/events"):
        assert client.get(path).status_code == 200, path


def test_the_right_token_gets_through(client, monkeypatch):
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")
    r = client.post("/mandates", headers={"X-Demo-Token": "s3cret"},
                    json={"budget_paise": 1000, "purpose": "x"})
    assert r.status_code == 200


def test_a_wrong_token_does_not(client, monkeypatch):
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")
    for wrong in ("", "s3cre", "s3cretx", "S3CRET", "x" * 64):
        r = client.post("/mandates", headers={"X-Demo-Token": wrong},
                        json={"budget_paise": 1000, "purpose": "x"})
        assert r.status_code == 401, f"{wrong!r} got through"


def test_surrounding_whitespace_is_forgiven(client, monkeypatch):
    """Deliberate. This is a token a person pastes out of a submission form, and
    a trailing newline turning into "it just doesn't work" costs more than the
    nothing it buys - the token is public by design, so tolerance here widens no
    secret space. The comparison is still constant-time and still exact."""
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")
    r = client.post("/mandates", headers={"X-Demo-Token": "  s3cret\n"},
                    json={"budget_paise": 1000, "purpose": "x"})
    assert r.status_code == 200


def test_runs_are_rate_limited_only_on_a_public_deployment(client, monkeypatch):
    monkeypatch.setattr(gateway, "DEMO_TOKEN", "s3cret")
    monkeypatch.setattr(gateway, "RUN_LIMIT", 2)
    monkeypatch.setattr(gateway, "_recent_runs", [])

    body = {"task": "restock", "budget_paise": 40_000 * RUPEE, "fan_out": 3,
            "floor_paise": 11_000 * RUPEE, "decomposer": "departmental",
            "monitor": False}
    head = {"X-Demo-Token": "s3cret"}
    assert client.post("/runs", headers=head, json=body).status_code == 200
    assert client.post("/runs", headers=head, json=body).status_code == 200

    blocked = client.post("/runs", headers=head, json=body)
    assert blocked.status_code == 429
    assert "retry_after_seconds" in blocked.json()["detail"]


# --- DEFER: the third verdict --------------------------------------------
#
# It was offered to the model and ignored. A "spend less than this" answer fell
# through to a full settlement and was recorded as `monitor: defer`, which reads
# like consent.


def _defer_monitor(amount_paise, reason="too much for a restock"):
    from pocketchange.monitor import Judgement, Verdict

    class Deferring:
        def judge(self, situation):
            return Judgement(Verdict.DEFER, reason, 0.8,
                             suggested_amount_paise=amount_paise)
    return Deferring()


def test_a_deferred_payment_settles_at_the_smaller_amount(client, mandate):
    gateway.state.monitor = _defer_monitor(200 * RUPEE)
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 900 * RUPEE, "cart": {"STA-A4-5": 9},
        "context": "nine reams of paper",
    })
    assert r.status_code == 200
    assert r.json()["amount_paise"] == 200 * RUPEE

    # And the ledger moved by the reduced figure, not the requested one.
    ledger = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert ledger["committed_paise"] == 200 * RUPEE


def test_the_audit_shows_both_figures(client, mandate):
    """A payment reduced by judgement must never read as one simply approved."""
    gateway.state.monitor = _defer_monitor(200 * RUPEE)
    client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 900 * RUPEE, "cart": {"STA-A4-5": 9}, "context": "paper",
    })
    paid = [e for e in gateway.state.audit.entries()
            if e.tool == "pay" and e.decision is Decision.ALLOWED][-1]
    assert paid.amount_paise == 200 * RUPEE
    assert paid.detail["requested_paise"] == 900 * RUPEE
    assert paid.detail["deferred_from_paise"] == 900 * RUPEE
    assert paid.detail["monitor"] == "defer"


def test_a_defer_with_no_usable_amount_asks_a_person_instead_of_guessing(client, mandate):
    """Inventing a safer figure on the model's behalf is a decision nobody
    authorised."""
    for useless in (None, 0, 900 * RUPEE, 5_000 * RUPEE):   # missing, zero, not smaller
        gateway.state.monitor = _defer_monitor(useless)
        r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
            "amount_paise": 900 * RUPEE, "cart": {"STA-A4-5": 9, "n": repr(useless)},
            "context": "paper",
        })
        assert r.status_code == 202, f"{useless!r} should have escalated"
        assert "without a usable amount" in r.json()["detail"]["reason"]


def test_an_escalation_after_a_defer_holds_the_reduced_amount(client, mandate):
    gateway.state.monitor = _defer_monitor(None)
    r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 900 * RUPEE, "cart": {"STA-A4-5": 9}, "context": "paper",
    })
    assert r.status_code == 202
    pending = client.get("/approvals").json()["pending"][0]
    assert pending["amount_paise"] == 900 * RUPEE     # nothing was reduced


def test_a_deferred_payment_replays_as_the_reduced_one(client, mandate):
    """The idempotency key is derived from the cart, which did not change - so a
    repeat returns this payment rather than becoming a second, larger one."""
    gateway.state.monitor = _defer_monitor(200 * RUPEE)
    body = {"amount_paise": 900 * RUPEE, "cart": {"STA-A4-5": 9}, "context": "paper"}
    first = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json=body).json()
    again = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json=body).json()

    assert again["replayed"] is True
    assert again["order_id"] == first["order_id"]
    assert again["amount_paise"] == 200 * RUPEE
    ledger = client.get(f"/mandates/{mandate['mandate_id']}").json()
    assert ledger["committed_paise"] == 200 * RUPEE


# --- what this deployment can actually do -----------------------------------


def test_status_reports_which_layers_are_real(client):
    """A deployment that cannot say which of its layers exist is not one anyone
    should trust with money. The console renders a degraded run and a full one
    identically without this."""
    body = client.get("/status").json()
    can = body["capabilities"]
    assert set(can) >= {"rail", "model", "decomposer", "monitor", "critic", "degraded"}
    # Test mode, always. There is no configuration that makes this true.
    assert can["payments_are_real"] is False


def test_status_names_an_unjudged_deployment_as_degraded(client, monkeypatch):
    from pocketchange import gateway
    from pocketchange.monitor import from_env

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    gateway.state.monitor = from_env()

    can = client.get("/status").json()["capabilities"]
    assert can["monitor"] == "unconfigured"
    assert can["decomposer"] == "departmental"
    assert can["degraded"] and "no model is configured" in can["degraded"]
