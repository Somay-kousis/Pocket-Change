"""L1b checkpoint: the agent mints its own mandates, one per seller.

No model is involved. This exercises the delegation machinery directly, so it
runs in a second and shows the property without spending quota:

  human  ──►  broker (delegate only, cannot spend)
                ├── sub-mandate  seller A  pay, capped at A's subtotal
                ├── sub-mandate  seller B  pay, capped at B's subtotal
                └── sub-mandate  seller C  pay, capped at C's subtotal

Three things worth watching:
  * the broker cannot pay, only delegate
  * each sub-payer can lose one seller's money and nothing else
  * every child shares the parent's mandate id, so one ceiling covers the tree

Run:  .venv/bin/python scripts/demo_delegation.py
"""

from fastapi.testclient import TestClient

from agent.tools import ToolSurface
from merchant import offers
from merchant.catalog import RUPEE
from pocketchange import gateway
from pocketchange.razorpay_client import FakeRail
from pocketchange.monitor import ScriptedMonitor, Verdict

BASKET = {"LAP-STD-1": 4, "MON-27Q-1": 2, "CHR-ERG-1": 1, "DSK-ADJ-1": 1, "KVM-DCK-1": 1}
BAR = "-" * 72


def heading(text):
    print(f"\n{text}\n{BAR}")


def cheapest_lines():
    """What a thrifty shopper would propose: cheapest available offer per line."""
    lines = []
    for sku, qty in BASKET.items():
        available = offers.available_offers(sku, qty)
        if available:
            lines.append({"sku": sku, "quantity": qty, "seller_id": available[0].seller_id})
    return lines


def main() -> int:
    gateway.state = gateway.State()
    # Pinned, not inherited: State() reads .env, so on a configured machine this
    # would create real Razorpay test orders while the README lists it as running
    # offline with no credentials.
    gateway.state.rail = FakeRail()
    gateway.state.monitor = ScriptedMonitor(Verdict.ALLOW, "pinned for L1b")
    client = TestClient(gateway.app, headers=gateway.local_operator_headers())

    mandate = client.post("/mandates", json={
        "budget_paise": 600_000 * RUPEE,
        "purpose": "weekly groceries, under 1500 rupees",
        "ttl_seconds": 3600,
    }).json()

    heading("AUTHORITY")
    print(f"  human mandate      Rs {mandate['budget_paise'] // RUPEE}")
    print(f"  mandate id         {mandate['mandate_id'][:32]}")

    shopper = client.post("/delegate", json={
        "token": mandate["token"], "tools": ["search", "cart"],
        "budget_paise": 600_000 * RUPEE, "context": "browsing listings",
    }).json()["token"]
    broker = client.post("/delegate", json={
        "token": mandate["token"], "tools": ["delegate", "pay"],
        "budget_paise": 600_000 * RUPEE, "context": "splitting the cart by seller",
        "to": "aip:web:pocketchange.dev/broker",
    }).json()["token"]
    print("  shopper            tool:search, tool:cart")
    print("  broker             tool:delegate, tool:pay")
    print("                     (it MUST hold pay to confer pay - attenuation is")
    print("                      monotonic. Spending is blocked by gateway policy,")
    print("                      not by the token. See token.is_broker.)")

    heading("THE BROKER MAY GRANT, NOT SPEND  (policy, not cryptography)")
    r = client.post("/pay", headers={"X-AIP-Token": broker}, json={
        "amount_paise": 40_000 * RUPEE, "cart": {"LAP-STD-1": 1},
        "context": "trying to pay directly instead of delegating",
    })
    print(f"  broker pays        {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:52]}")

    heading("A SHOPPER CANNOT MINT ITSELF A PAYER")
    r = client.post("/delegate", json={
        "token": shopper, "tools": ["pay"], "budget_paise": 40_000 * RUPEE,
        "context": "minting myself the ability to pay", "depth": 1,
    })
    print(f"  shopper delegates  {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:52]}")

    tools = ToolSurface(client=client, shopper_token=shopper,
                        payer_token="", broker_token=broker)
    tools.propose_cart("thrifty", cheapest_lines(), "cheapest available per line")
    tools.choose_cart("thrifty", "only proposal in this demo")

    split = tools.split_by_seller()
    heading("THE CART SPLITS")
    print(f"  total              Rs {split['total_paise'] / 100:.2f} "
          f"across {split['seller_count']} sellers\n")
    for group in split["groups"]:
        skus = ", ".join(f"{line['sku']}x{line['quantity']}" for line in group["lines"])
        print(f"  {group['seller_id']:<20} Rs {group['subtotal_paise'] / 100:>8.2f}   {skus}")

    heading("THE BROKER MINTS ONE MANDATE PER SELLER")
    for group in split["groups"]:
        seller = group["seller_id"]
        out = tools.delegate_for_seller(seller, f"paying {seller} for its part of the cart")
        print(f"  {seller:<20} cap Rs {out['cap_paise'] / 100:>8.2f}   "
              f"expires {str(out.get('expires'))[11:19]}")

    heading("EACH SUB-PAYER SPENDS ONLY ITS OWN SELLER'S SHARE")
    for group in split["groups"]:
        seller = group["seller_id"]
        paid = tools.checkout_seller(seller, f"settling the {seller} portion of the weekly shop")
        if "order_id" in paid:
            print(f"  {seller:<20} {paid['order_id']:<24} "
                  f"remaining Rs {paid['remaining_paise'] / 100:.2f}")
        else:
            print(f"  {seller:<20} REFUSED  {paid.get('refused')}")

    heading("A SUB-PAYER CANNOT OVERSPEND ITS CAP")
    victim = split["groups"][0]["seller_id"]
    r = client.post("/pay", headers={"X-AIP-Token": tools.sub_mandates[victim]}, json={
        "amount_paise": 360_000 * RUPEE, "cart": {"SRV-RCK-1": 2},
        "context": "a compromised sub-payer trying to spend the whole mandate",
    })
    print(f"  {victim:<20} {r.status_code}  "
          f"{r.json().get('detail', {}).get('denied', '')[:52]}")

    heading("AUDIT: ONE MANDATE, A TREE OF DELEGATIONS")
    trail = client.get("/audit").json()
    print(f"  {trail['count']} entries, chain intact {trail['intact']}\n")
    for e in trail["entries"]:
        mark = "ok " if e["decision"] == "allowed" else "REF"
        amount = f"Rs {e['amount_paise'] // RUPEE}" if e["amount_paise"] else ""
        print(f"  {mark} {e['tool']:<10} {amount:>8}  {e['reason'][:44]}")

    state = client.get(f"/mandates/{mandate['mandate_id']}").json()
    print(f"\n  one ceiling over the whole tree: "
          f"committed Rs {state['committed_paise'] / 100:.2f} "
          f"of Rs {state['cap_paise'] / 100:.2f}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
