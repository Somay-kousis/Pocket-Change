"""Two reputations, side by side: the seller's, and ours.

The buyer has always been able to ask a supplier how good it is. That is what
`seller_reputation()` returns, and every figure in it - rating, review count,
months trading - lives in the supplier's own record. A hostile supplier fills it
in itself and is "established" for free. SoK calls this Identity-to-Market, and
this project marked it NOT APPLICABLE for months on the grounds that there is no
market here to move. That was too convenient: sybil reputation needs no market,
only a party whose word is taken for its own standing.

The gateway now keeps its own record, written at settlement from payments that
actually cleared. Watch what each of them says about the same two suppliers.

Offline: fake rail, scripted monitor, no credentials.

Run:  .venv/bin/python scripts/demo_trust.py
"""

from fastapi.testclient import TestClient

from merchant import sellers
from pocketchange import gateway
from pocketchange.monitor import ScriptedMonitor, Verdict
from pocketchange.policy import RUPEE
from pocketchange.counterparties import InMemoryCounterparties
from pocketchange.razorpay_client import FakeRail

BAR = "─" * 72
KNOWN = "meridian-systems"          # long-standing on the vendor register
FRAUD = "bestdeals-procurement"     # the adversarial page in merchant/web_index.py


def heading(text: str) -> None:
    print(f"\n\033[1m{text}\033[0m\n{BAR}")


def main() -> int:
    gateway.state = gateway.State()
    gateway.state.rail = FakeRail()
    # Pinned too. State() reaches Firestore when a project is configured, so on a
    # configured machine this demo would accumulate history across runs and print
    # different numbers every time - which is the durability working, and useless
    # in something meant to be reproducible.
    gateway.state.counterparties = InMemoryCounterparties()
    seen = ScriptedMonitor(verdict=Verdict.ALLOW)
    gateway.state.monitor = seen
    client = TestClient(gateway.app, headers=gateway.local_operator_headers())

    mandate = client.post("/mandates", json={
        "budget_paise": 500_000 * RUPEE, "purpose": "restock the office",
        "ttl_seconds": 3600,
    }).json()

    heading("1. WHAT THE SELLER SAYS ABOUT ITSELF")
    print("  merchant/sellers.py, read by the shopper through seller_reputation()\n")
    known = sellers.get(KNOWN)
    print(f"  {KNOWN:<26} rating {known.rating}  "
          f"{known.review_count:,} reviews  {known.trading_months} months  "
          f"established={known.is_established}")
    print(f"\n  Every one of those numbers is in the seller's own record.")
    print(f"  is_established is `trading_months >= 12 and review_count >= 100`.")
    print(f"  A supplier that writes 100 reviews for itself clears that bar.")

    heading("2. WHAT WE HAVE ACTUALLY DONE")
    for n in range(1, 4):
        client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
            "amount_paise": 20_000 * RUPEE, "cart": {"LAP-STD-1": n},
            "context": f"laptop order {n}", "counterparty": KNOWN,
        })
    book = {c["id"]: c for c in client.get("/counterparties").json()["counterparties"]}
    print(f"  {KNOWN:<26} {book[KNOWN]['orders']} orders, "
          f"Rs {book[KNOWN]['total_paise'] // 100:,} settled")
    print(f"  {FRAUD:<26} {'(no record)' if FRAUD not in book else book[FRAUD]}")
    print(f"\n  Written by the gateway at settlement. Nothing outside this")
    print(f"  process can add a row, so no amount of self-promotion appears here.")

    heading("3. WHAT THE MONITOR IS TOLD")
    before = len(seen.seen)
    client.post("/pay", headers={"X-AIP-Token": mandate["token"]}, json={
        "amount_paise": 90_000 * RUPEE, "cart": {"LAP-PRO-1": 9},
        "context": "a large order from a supplier the page recommended",
        "counterparty": FRAUD,
    })
    fraud_view = seen.seen[before]
    known_view = seen.seen[1]

    print(f"  paying {KNOWN}")
    print(f"    counterparty  {known_view.counterparty}")
    print(f"    our record    {known_view.counterparty_history}")
    print(f"\n  paying {FRAUD}  (Rs 90,000, first time)")
    print(f"    counterparty  {fraud_view.counterparty}")
    print(f"    our record    {fraud_view.counterparty_history}")

    heading("4. A TALLY IS NOT A REPUTATION")
    from pocketchange import counterparties as cp

    for kind, label in ((cp.INJECTION, "a page from them carried injected instructions"),
                        (cp.VETOED, "a person looked at a payment and said no")):
        gateway.state.counterparties.flag(FRAUD, kind)
        print(f"  recorded: {label}")
    print(f"\n  {FRAUD} now reads:")
    print(f"    {gateway.state.counterparties.lookup(FRAUD).describe()}")
    print(f"\n  The order count did not change. Forty settled orders beside two")
    print(f"  refusals is a WORSE record than none - so the concerns lead, and a")
    print(f"  long tally cannot be used as cover.")
    print(f"\n  Measured against the live monitor: the same routine purchase is")
    print(f"  ALLOWED from a 34-order supplier with a clean record and ESCALATED")
    print(f"  from one with the same tally plus concerns. The count alone moved")
    print(f"  nothing; how the dealings went moved the verdict.")

    heading("5. WHAT THIS DOES AND DOES NOT PROVE")
    print("  proves     a supplier cannot manufacture a history with us. The")
    print("             record comes from payments that cleared, and only the")
    print("             gateway writes it.")
    print("  does NOT   prove the supplier is honest, or that the agent named")
    print("             the right one. The identity on a payment is still")
    print("             agent-supplied and still misattributable. What cannot")
    print("             be forged is the history behind the name.")
    print("\n  So this is evidence for the monitor to weigh, not a permission")
    print("  check. Enforcement never consults it: a token that may spend may")
    print("  spend, whoever it is paying.")

    ok = (book[KNOWN]["orders"] == 3 and FRAUD not in book
          and "never paid before" in fraud_view.counterparty_history
          and "never" not in known_view.counterparty_history)
    print(f"\n  \033[1m{'PASS' if ok else 'FAIL'}\033[0m\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
