"""Stage 1 checkpoint: the agent is refused, re-plans, and succeeds.

The setup is deliberate. A first purchase of 858 rupees is made against a 1500
rupee mandate, leaving 642. The agent is then asked for a cart worth 868 - which
its token permits, because 868 is under the mandate's 1500 ceiling. Only the
ledger knows the money is already spent.

So the refusal is cumulative spend: the exact gap AIP declares out of scope. The
agent cannot argue with it, cannot widen anything, and cannot retry the same cart.
It has to buy less.

That is the whole claim in one run - not blocked autonomy, bounded autonomy.

Run:  .venv/bin/python scripts/demo_replan.py
"""

import asyncio

from fastapi.testclient import TestClient

from agent.graph import run_errand
from agent.tools import ToolSurface
from merchant.catalog import RUPEE
from pocketchange import config, gateway
from pocketchange.monitor import ScriptedMonitor, Verdict

BAR = "-" * 70


def heading(text):
    print(f"\n{text}\n{BAR}")



async def main() -> int:
    config.load()
    gateway.state = gateway.State()
    # Stage 1 isolates the re-planning loop, so the semantic monitor is pinned to
    # allow. It gets its own demo in stage 2, and running it here would spend the
    # 15-per-minute model quota on a question this scenario is not asking.
    gateway.state.monitor = ScriptedMonitor(Verdict.ALLOW, "pinned for stage 1")

    client = TestClient(gateway.app, headers=gateway.local_operator_headers())

    mandate = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE,
        "purpose": "weekly groceries, under 1500 rupees",
        "ttl_seconds": 3600,
    }).json()
    root = mandate["token"]

    shopper_token = client.post("/delegate", json={
        "token": root, "tools": ["search", "cart"], "budget_paise": 600_000 * RUPEE,
        "context": "browsing listings for the grocery run",
    }).json()["token"]
    payer_token = client.post("/delegate", json={
        "token": root, "tools": ["pay"], "budget_paise": 600_000 * RUPEE,
        "context": "paying for the assembled cart",
    }).json()["token"]

    heading("SETUP")
    print(f"  mandate            Rs {mandate['budget_paise'] // RUPEE}")

    seed = client.post("/pay", headers={"X-AIP-Token": payer_token}, json={
        "amount_paise": 343_200 * RUPEE,
        "cart": {"SRV-RCK-1": 2, "TNR-LSR-1": 1},
        "context": "earlier purchase this hour: ghee and turmeric",
    }).json()
    print(f"  earlier purchase   Rs 858   -> {seed['order_id']}")
    print(f"  remaining          Rs {seed['remaining_paise'] // RUPEE}"
          f"   (the agent is not told this)")

    tools = ToolSurface(client=client, shopper_token=shopper_token,
                        payer_token=payer_token)

    heading("THE ERRAND")
    print("  request            4 kg rice, 2 kg toor dal, 1 L groundnut oil")
    print("                     = Rs 868, which the TOKEN permits\n")

    result = await run_errand(
        tools,
        "Buy 4 kg of Sona Masoori rice, 2 kg of toor dal and 1 litre of "
        "groundnut oil for the week.",
        on_event=lambda line: print(f"  {line[:96]}"),
    )

    heading("COMPETING CARTS")
    for a in tools.attempts:
        if a.tool == "propose_cart":
            r = a.result
            print(f"  {r['strategy']:<10} Rs {r['total_paise'] // RUPEE:>5}  {r['items']}")
            print(f"  {'':<10} {r['rationale'][:70]}")
    if tools.chosen_strategy:
        print(f"\n  chose      {tools.chosen_strategy}")
        print(f"  because    {tools.choice_reason[:78]}")

    heading("WHAT THE AGENT DID")
    for a in tools.attempts:
        mark = "ok " if a.allowed else "REF"
        extra = ""
        if not a.allowed and isinstance(a.result, dict):
            d = a.result.get("detail", a.result)
            if isinstance(d, dict) and "denied" in d:
                extra = f"  {d['denied']}"
        print(f"  {mark} {a.tool:<18} {a.status}{extra}")

    heading("OUTCOME")
    s = result.summary()
    for k in ("rounds", "proposals", "refusals", "paid", "replanned"):
        print(f"  {k:<12} {s[k]}")
    print(f"  cart         {s['cart']}")
    print(f"  reviewer     {s['outcome']}")

    trail = client.get("/audit").json()
    print(f"\n  audit: {trail['count']} entries, intact {trail['intact']}")
    for e in trail["entries"]:
        mark = "ok " if e["decision"] == "allowed" else "REF"
        amt = f"Rs {e['amount_paise'] // RUPEE}" if e["amount_paise"] else ""
        print(f"    {mark} {e['tool']:<8} {amt:>8}  {e['reason'][:44]}")

    print(f"\n{BAR}")
    if s["replanned"]:
        print("  The agent was refused, re-planned within the money that was")
        print("  actually left, and completed the errand. Bounded autonomy.")
    elif s["refusals"] and not s["paid"]:
        print("  Refused and could not recover. The loop terminated cleanly,")
        print("  which is correct if no affordable cart existed - check above.")
    else:
        print("  No refusal occurred. The scenario did not exercise the loop.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
