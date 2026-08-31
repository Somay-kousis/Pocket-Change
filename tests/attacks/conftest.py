"""The attack corpus: shared harness, attacker markers, and the final tally.

Every case here is an attempt to get money or authority the caller was never
given. A case PASSES when the attack FAILS. Each one checks the money, not just
the status code: no new rail order, no committed spend moved on any mandate or
delegated envelope, and, where the gateway saw the attempt, a denial in the
audit with the chain still intact.

Three attackers, one marker each, enforced at collection:

  agent    a compromised agent holding a real token
  seller   a hostile seller writing pages, listings and reviews
  network  someone with network access and no token at all

A deliberate limitation the README already states is xfail(strict=True) with
the README's own words as the reason. Strict, so the day one of them is fixed
the suite says so instead of quietly passing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pocketchange import gateway
from pocketchange.audit import Decision
from pocketchange.monitor import ScriptedMonitor, Verdict
from tests._operator import OPERATOR_HEADERS

ATTACKERS = {
    "agent": "a compromised agent holding a real token",
    "seller": "a hostile seller writing pages, listings and reviews",
    "network": "network access only, no token",
}
HERE = Path(__file__).parent
REGISTER = "test_register.py"

# README limitations, quoted, for xfail reasons. One place, so the wording in
# the corpus cannot drift from the wording in the README.
LIMIT_DEMO_GATE = "README Limitations: The demo gate is not authentication."
LIMIT_MISATTRIBUTION = ("README Limitations: The counterparty identity is agent-supplied "
                        "and therefore misattributable.")
LIMIT_FAILS_OPEN = "README Limitations: The monitor fails open."
LIMIT_NO_REVOCATION = "README Limitations: No revocation."
LIMIT_POLICY_SEPARATION = ("README Limitations: Branch separation is policy, not "
                           "cryptography.")


def _is_attack(item) -> bool:
    path = Path(str(item.fspath))
    return path.parent == HERE and path.name != REGISTER


def pytest_configure(config):
    for name, what in ATTACKERS.items():
        config.addinivalue_line("markers", f"{name}: attack by {what}")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if not _is_attack(item):
            continue
        who = [m.name for m in item.iter_markers() if m.name in ATTACKERS]
        if len(who) != 1:
            raise pytest.UsageError(
                f"{item.nodeid}: every attack names exactly one attacker "
                f"({', '.join(ATTACKERS)}), found {who or 'none'}")


def pytest_terminal_summary(terminalreporter):
    """The one line the README quotes: what was tried and what held."""
    stats = terminalreporter.stats
    tally = {"blocked": 0, "known": 0, "landed": 0}
    by_attacker = {name: 0 for name in ATTACKERS}

    def ours(report) -> bool:
        path = report.nodeid.split("::")[0]
        return "tests/attacks/" in path and not path.endswith(REGISTER)

    seen = set()
    for key, outcome in (("passed", "blocked"), ("xfailed", "known"),
                         ("failed", "landed"), ("xpassed", "landed"), ("error", "landed")):
        for report in stats.get(key, []):
            if not ours(report) or report.nodeid in seen:
                continue
            if key == "passed" and report.when != "call":
                continue
            seen.add(report.nodeid)
            tally[outcome] += 1
            for name in ATTACKERS:
                if name in report.keywords:
                    by_attacker[name] += 1
    total = sum(tally.values())
    if not total:
        return
    line = f"{total} attacks, {tally['blocked']} blocked, {tally['known']} known limits"
    if tally["landed"]:
        line += f", {tally['landed']} LANDED"
    who = ", ".join(f"{by_attacker[n]} {n}" for n in ATTACKERS)
    terminalreporter.write_sep("=", f"{line} ({who})")


# --- the harness ---------------------------------------------------------------

OFFICE_CART = {"STA-A4-5": 2}


@dataclass
class Snapshot:
    orders: int
    committed: dict[str, int]
    reserved: dict[str, int]
    audit_len: int


@dataclass
class Gateway:
    """A fresh gateway, an agent with no operator credential, and an operator."""

    state: gateway.State = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        gateway.state = gateway.State()
        self.state = gateway.state
        # raise_server_exceptions=False: a 500 must arrive as a response the
        # assertion can name, not as an exception that reads like a test bug.
        self.agent = TestClient(gateway.app, raise_server_exceptions=False)
        self.operator = TestClient(gateway.app, headers=OPERATOR_HEADERS,
                                   raise_server_exceptions=False)

    # --- authority, as the operator grants it --------------------------------

    def mandate(self, budget: int = 100_000, *, ttl: int = 3600, depth: int = 3,
                purpose: str = "stationery and toner for the design studio") -> dict:
        r = self.operator.post("/mandates", json={
            "budget_paise": budget, "ttl_seconds": ttl, "max_depth": depth,
            "purpose": purpose})
        assert r.status_code == 200, r.text
        return r.json()

    def delegate(self, parent: str, tools=("pay",), budget: int = 10_000, *,
                 to: str | None = None, ttl: int | None = None,
                 context: str = "narrowing for one supplier") -> str:
        body = {"token": parent, "tools": list(tools), "budget_paise": budget,
                "context": context}
        if to is not None:
            body["to"] = to
        if ttl is not None:
            body["ttl_seconds"] = ttl
        r = self.agent.post("/delegate", json=body)
        assert r.status_code == 200, r.text
        return r.json()["token"]

    def monitor(self, verdict: Verdict, reason: str = "scripted for the attack") -> None:
        self.state.monitor = ScriptedMonitor(verdict, reason)

    # --- what the agent sends ------------------------------------------------

    def pay(self, tok: str | None, amount, cart=None, context: str = "restocking paper",
            **extra):
        headers = {"X-AIP-Token": tok} if tok is not None else {}
        body = {"amount_paise": amount, "cart": OFFICE_CART if cart is None else cart,
                "context": context, **extra}
        return self.agent.post("/pay", headers=headers, json=body)

    def escalate(self, tok: str, amount: int = 5_000, cart=None) -> str:
        """Get one payment held for a person; returns the approval id."""
        self.monitor(Verdict.ESCALATE, "forty reams is not a studio's monthly use")
        r = self.pay(tok, amount, cart or {"STA-A4-5": 40})
        assert r.status_code == 202, r.text
        return r.json()["detail"]["approval_id"]

    # --- the money -----------------------------------------------------------

    def snapshot(self) -> Snapshot:
        books = self.state.ledger._mandates
        return Snapshot(
            orders=len(self.state.rail.orders),
            committed={k: m.committed_paise for k, m in books.items()},
            reserved={k: m.reserved_paise for k, m in books.items()},
            audit_len=len(self.state.audit),
        )

    def denials_since(self, snap: Snapshot, tool: str | None = None) -> list:
        fresh = self.state.audit.entries()[snap.audit_len:]
        return [e for e in fresh if e.decision is Decision.DENIED
                and (tool is None or e.tool == tool)]

    def unmoved(self, snap: Snapshot, *, reserved: bool = True) -> None:
        """No order reached the rail and no spend moved anywhere."""
        now = self.snapshot()
        assert now.orders == snap.orders, (
            f"the rail took {now.orders - snap.orders} new order(s)")
        for key, committed in now.committed.items():
            assert committed == snap.committed.get(key, 0), (
                f"committed spend moved on {key[:24]}: "
                f"{snap.committed.get(key, 0)} -> {committed}")
        if reserved:
            for key, held in now.reserved.items():
                assert held == snap.reserved.get(key, 0), (
                    f"budget is held on {key[:24]}: {held}")
        self.state.audit.verify()

    def blocked(self, response, status, snap: Snapshot, *, audit: str | bool | None = True,
                reserved: bool = True) -> None:
        """The attack failed: the expected refusal, no money, and a record of it.

        `audit` is True for any denial, a tool name to require that tool, or
        False where the request never reached a handler (schema refusals).
        """
        allowed = status if isinstance(status, (set, tuple)) else {status}
        assert response.status_code != 500, f"server error: {response.text[:300]}"
        assert response.status_code in allowed, (
            f"expected {sorted(allowed)}, got {response.status_code}: {response.text[:300]}")
        self.unmoved(snap, reserved=reserved)
        if audit:
            tool = audit if isinstance(audit, str) else None
            assert self.denials_since(snap, tool), (
                f"no denial recorded in the audit{f' for {tool}' if tool else ''}")


@pytest.fixture
def gw() -> Gateway:
    return Gateway()
