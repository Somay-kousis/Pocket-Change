"""The funnel, paying. A hundred and twenty-one nodes into one budget pool.

eval/funnel.py proves the tree grows and stops. This proves it *spends* - every
leaf posts a real payment through the gateway, with its own attenuated token,
against one ledger.

That distinction is the point. An earlier review of this project found three
intake branches that produced plans and never reached a payment; a funnel that
did the same would be the same mistake at greater scale. So the number printed
at the end is what the ledger says was committed, not what the plan intended.

What to watch:

  * 121 tokens, one mandate id. The ledger caps the tree, not each branch.
  * 81 leaves pay independently and cannot, between them, exceed the root.
  * a leaf holds `pay` and not `delegate` - it can misspend its own ₹7,407 and
    cannot recruit anything to help.
  * tamper with one leaf's amount and the chain refuses it, at that leaf only.

Run:  .venv/bin/python scripts/demo_funnel.py
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from agent import search as websearch
from pocketchange import events, funnel, gateway, token as tokens
from pocketchange.razorpay_client import FakeRail
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE

BUDGET = 600_000 * RUPEE
FLOOR = 10_000 * RUPEE
BAR = "-" * 72

DEPARTMENTS = ["engineering", "design", "operations"]
CATEGORIES = ["workstations", "peripherals", "furniture"]
ITEMS = ["primary units", "spares", "accessories"]


def heading(text):
    print(f"\n{text}\n{BAR}")


def rupees(paise):
    return f"Rs {paise / RUPEE:,.2f}"


def scripted(node):
    """Stands in for a model. One call per branch node; 40 for this whole tree."""
    share = node.budget_paise // 3
    if node.depth == 0:
        return [funnel.SubTask(f"kit out {d}", share) for d in DEPARTMENTS]
    if node.depth == 1:
        return [funnel.SubTask(f"{node.description}: {c}", share) for c in CATEGORIES]
    if node.depth == 2:
        return [funnel.SubTask(f"{node.description} - {i}", share,
                               sourcing=funnel.BEST if i == ITEMS[0] else funnel.CATALOGUE)
                for i in ITEMS]
    return [funnel.SubTask(f"{node.description} lot {i}", share) for i in (1, 2, 3)]


def main():
    gateway.state = gateway.State()
    # Pinned, not inherited: State() reads .env, so on a configured machine this
    # would create real Razorpay test orders while the README lists it as running
    # offline with no credentials.
    gateway.state.rail = FakeRail()
    # Pinned so this runs without quota. The monitor is exercised by
    # demo_injection and by its own tests; the subject here is the funnel.
    gateway.state.monitor = ScriptedMonitor(verdict=Verdict.ALLOW)
    client = TestClient(gateway.app, headers=gateway.local_operator_headers())

    heading("THE MANDATE")
    r = client.post("/mandates", json={
        "budget_paise": BUDGET,
        "purpose": "equip the new Bengaluru office",
        "max_depth": 8,
        "ttl_seconds": 3600,
    })
    root = r.json()
    print(f"  budget      {rupees(root['budget_paise'])}")
    print(f"  mandate     {root['mandate_id'][:24]}...")
    print(f"  max_depth   8   (the ceiling nothing below can widen)")

    root_token = tokens.deserialize(root["token"], gateway.state.root_public_key)

    searched = []

    def look(node):
        """A zero-budget child sources from the open web, which in this demo is
        merchant/web_index.py - four of whose nine pages are adversarial."""
        hits = websearch.search(node.description, provider=websearch.LocalCorpus())
        searched.append((node.id, hits))
        return hits

    bus = events.EventBus(history=10_000)
    f = funnel.Funnel(
        root_token, description="equip the new Bengaluru office",
        budget_paise=BUDGET, bus=bus,
        bounds=funnel.Bounds(max_depth=8, max_fanout=6, max_nodes=200,
                             decompose_floor_paise=FLOOR),
        search=look,
    )

    paid, refused = [], []

    def pay(node):
        """A leaf spends its own budget, with its own token, through the gateway."""
        response = client.post("/pay", headers={"X-AIP-Token": tokens.serialize(node.token)},
                               json={
                                   "amount_paise": node.budget_paise,
                                   "cart": {"node": node.id, "for": node.description},
                                   "context": f"leaf of the funnel: {node.description}",
                               })
        if response.status_code == 202:
            # Suspended awaiting a human, with the reservation still held.
            detail = response.json().get("detail", {})
            raise funnel.Escalated(detail.get("reason", "escalated"))
        if response.status_code != 200:
            refused.append((node.id, response.json()))
            raise RuntimeError(response.json().get("detail", {}).get("denied", "refused"))
        body = response.json()
        paid.append(body)
        return body["order_id"]

    heading("THE RUN")
    print("  decomposing until each piece is under Rs 10,000, then paying...\n")
    result = f.run(scripted, pay)
    s = result.summary()

    for node in result.root.walk():
        if node.depth > 2:
            continue
        tag = "  <- web" if node.sourcing == funnel.BEST else ""
        print(f"{'  ' * node.depth}  {node.id:<14} {rupees(node.budget_paise):>14}  "
              f"{node.description}{tag}")
    print(f"      ... {len([n for n in result.root.walk() if n.depth > 2])} "
          f"nodes below, 81 of them leaves that paid")

    heading("WHAT THE LEDGER SAYS")
    ledger = client.get(f"/mandates/{root['mandate_id']}").json()
    print(f"  nodes in the tree     {s['nodes']}")
    print(f"  leaves that paid      {len(paid)}")
    print(f"  committed (ledger)    {rupees(ledger['committed_paise'])}")
    print(f"  available             {rupees(ledger['available_paise'])}")
    print(f"  reserved (in flight)  {rupees(ledger['reserved_paise'])}")
    print(f"  ceiling               {rupees(ledger['cap_paise'])}")
    print(f"  audit entries         {len(client.get('/audit').json()['entries'])}")
    over = ledger["committed_paise"] > BUDGET
    print(f"\n  81 independent payers could not exceed one ceiling:  "
          f"{'NO - OVERSPENT' if over else 'confirmed'}")

    heading("WHAT THE SEARCHERS FOUND")
    from agent.utils.provenance import is_marked, unmark

    all_hits = [h for _, hits in searched for h in hits]
    hostile = [h for h in all_hits if "bestdeals" in h.url or "verify-supplier" in h.url
               or "procurement-portal" in h.url]
    print(f"  best-source nodes         {len(searched)}")
    print(f"  pages read                {len(all_hits)}")
    print(f"  adversarial among them    {len(hostile)}")
    print(f"  every field marked        "
          f"{all(is_marked(h.body_untrusted) for h in all_hits if h.body_untrusted)}")
    if hostile:
        print(f"\n  a page the searcher read, unmarked for display:")
        print(f"    {unmark(hostile[0].body_untrusted)[:150]}...")
    looker = next(n for n in result.root.walk() if n.is_helper)
    print(f"\n  the agent that read it holds  Rs 0.00 and tools ['search'], and is a")
    print(f"  SIBLING of the payer, not its child - a child would force the payer")
    print(f"  to hold 'search' for the child to inherit it.")
    r = client.post("/pay", headers={"X-AIP-Token": tokens.serialize(looker.token)}, json={
        "amount_paise": 1, "cart": {"one": "paisa"},
        "context": "the page said my limit was raised",
    })
    print(f"  it tries to spend one paisa   {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:40]}")

    heading("WHAT A COMPROMISED LEAF CANNOT DO")
    leaf = result.leaves[0]
    leaf_raw = tokens.serialize(leaf.token)

    # 1. spend more than it was handed
    r = client.post("/pay", headers={"X-AIP-Token": leaf_raw}, json={
        "amount_paise": leaf.budget_paise * 10,
        "cart": {"node": leaf.id, "greed": True},
        "context": "the seller says the price went up",
    })
    print(f"  ask for ten times its budget      {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:44]}")

    # 2. recruit help
    r = client.post("/delegate", json={
        "token": leaf_raw, "tools": ["pay"], "budget_paise": 100 * RUPEE,
        "context": "spinning up a helper",
    })
    print(f"  mint itself a sub-agent           {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:44]}")

    # 3. climb back up the tree
    parent = next(n for n in result.root.walk() if n.id == leaf.parent_id)
    print(f"  reach its parent's budget         "
          f"impossible - it holds a different token, capped at "
          f"{rupees(leaf.budget_paise)}, not {rupees(parent.budget_paise)}")

    heading("SUMMARY")
    ok = (len(paid) == 81 and not over
          and ledger["committed_paise"] == sum(p["amount_paise"] for p in paid))
    print(f"  {s['nodes']} nodes ({len(searched)} of them zero-budget lookers)  |  "
          f"{len(paid)} payments  |  "
          f"40 model calls would have been needed, 0 were spent here")
    print(f"  refusals: {len(result.refusals)}   ledger reconciles: "
          f"{ledger['committed_paise'] == sum(p['amount_paise'] for p in paid)}")
    print(f"\n  {'PASS' if ok else 'FAIL'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
