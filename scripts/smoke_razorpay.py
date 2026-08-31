"""Day-2 gate: one real Razorpay test-mode order, through the full check order.

Creates a mandate, pays once, replays the same cart, then overspends - and
prints the audit trail. Everything hits the real Razorpay sandbox.

Run:  .venv/bin/python scripts/smoke_razorpay.py
"""

from dotenv import load_dotenv

load_dotenv()  # must precede the gateway import: State() reads credentials at construction

from fastapi.testclient import TestClient  # noqa: E402

from pocketchange import gateway  # noqa: E402
from pocketchange.policy import RUPEE  # noqa: E402

gateway.state = gateway.State()
client = TestClient(gateway.app, headers=gateway.local_operator_headers())

health = client.get("/healthz").json()
print(f"rail: {health['rail']}")
if health["rail"] != "razorpay-test":
    raise SystemExit("credentials not loaded - expected the real test-mode rail")

mandate = client.post("/mandates", json={
    "budget_paise": 600_000 * RUPEE,
    "purpose": "weekly grocery run, under 1500 rupees",
    "ttl_seconds": 3600,
}).json()
print(f"mandate: {mandate['mandate_id'][:16]}  cap: {mandate['budget_paise']}p\n")

tok = mandate["token"]


def pay(amount, cart, label):
    r = client.post("/pay", headers={"X-AIP-Token": tok}, json={
        "amount_paise": amount, "cart": cart,
        "context": "buying the cart the shopper assembled",
    })
    body = r.json()
    if r.status_code == 200:
        flag = " (replayed)" if body["replayed"] else ""
        print(f"  {label:<34} {r.status_code}  {body['order_id']}{flag}")
        print(f"  {'':<34}      remaining {body['remaining_paise']}p")
    else:
        d = body.get("detail", body)
        print(f"  {label:<34} {r.status_code}  DENIED: {d.get('denied', d)}")
        if isinstance(d, dict) and "available" in d:
            print(f"  {'':<34}      available {d['available']}p of {d['cap']}p")
    return r


print("payments:")
pay(359_600 * RUPEE, {"rice": 4, "dal": 2}, "first purchase")
pay(359_600 * RUPEE, {"rice": 4, "dal": 2}, "same cart again")
pay(359_600 * RUPEE, {"atta": 5}, "different cart, over budget")

trail = client.get("/audit").json()
print(f"\naudit: {trail['count']} entries, chain intact: {trail['intact']}")
for e in trail["entries"]:
    print(f"  {e['seq']}  {e['decision']:<9} {e['tool']:<8} {e['reason']}")
