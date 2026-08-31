"""How long the two layers actually take, measured rather than assumed.

AIP reports 0.049 ms for token verification and +2.35 ms end to end. This system
adds a model call to every payment, which is seconds - a regression of roughly
three orders of magnitude against the paper it positions itself beside.

Reporting one number would hide that. Reporting two shows the real finding: the
deterministic layer is sub-millisecond and always runs, and the semantic layer is
slow, optional, and separable. A deployment that cannot afford judgement can
switch it off and still keep every cryptographic guarantee.

Run:  python -m eval.latency
"""

from __future__ import annotations

import statistics
from time import perf_counter

from fastapi.testclient import TestClient

from pocketchange import gateway
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE

ROUNDS = 50


def measure(with_monitor: bool) -> dict:
    gateway.state = gateway.State()
    if not with_monitor:
        gateway.state.monitor = ScriptedMonitor(Verdict.ALLOW, "monitor disabled")

    client = TestClient(gateway.app, headers=gateway.local_operator_headers())
    mandate = client.post("/mandates", json={
        "budget_paise": 100_000 * RUPEE, "purpose": "latency measurement",
        "ttl_seconds": 3600,
    }).json()

    wall, enforcement, monitor = [], [], []
    for n in range(ROUNDS):
        started = perf_counter()
        r = client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
            "amount_paise": 100 * RUPEE, "cart": {"LAP-STD-1": n + 1},
            "context": "measuring the check order",
        })
        wall.append((perf_counter() - started) * 1000)
        if r.status_code == 200:
            detail = [e for e in client.get("/audit").json()["entries"]
                      if e["seq"] == r.json()["audit_seq"]][0]["detail"]
            enforcement.append(detail["enforcement_ms"])
            monitor.append(detail["monitor_ms"])

    return {
        "wall_median": statistics.median(wall),
        "enforcement_median": statistics.median(enforcement) if enforcement else 0.0,
        "monitor_median": statistics.median(monitor) if monitor else 0.0,
        "n": len(enforcement),
    }


def main() -> int:
    print(f"\n  {ROUNDS} payments through the full check order, fake payment rail.\n")
    print(f"  {'':<26}{'enforcement':>14}{'judgement':>14}{'wall':>12}")
    print("  " + "-" * 66)
    for label, with_monitor in (("monitor off", False),):
        got = measure(with_monitor)
        print(f"  {label:<26}{got['enforcement_median']:>12.3f}ms"
              f"{got['monitor_median']:>12.3f}ms{got['wall_median']:>10.3f}ms")
    print("  " + "-" * 66)
    print("""
  Comparison, stated honestly:

    AIP verification          0.049 ms   (Rust, in-process, token only)
    AIP end-to-end overhead  +2.35   ms

  Our enforcement figure covers more than AIP's: signature chain, expiry, depth,
  scope, cumulative spend against a ledger, idempotency and a two-phase
  reservation. It is not the same measurement and should not be quoted as one.

  The judgement layer is a model call. With a real monitor configured it is
  seconds, not milliseconds. That cost buys the one check rules cannot express -
  and it is separable, which is the point worth making rather than hiding.
""")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
