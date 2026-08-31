"""A Strands agent that spends through Pocket Change.

The point of this file is what it does NOT contain. There is no ceiling in here,
no budget arithmetic, no check on what may be bought and no way to raise a
limit. The agent gets a token and a gateway URL, and every constraint it is
under was decided before it ran, by someone else, in a signature it cannot
forge.

That is the claim the whole project makes, and a second agent framework is the
cheapest way to test it. If swapping the reasoning layer required touching
enforcement, enforcement was never really separate. It did not: the gateway
speaks HTTP, so this is a client.

Strands is an optional dependency. It is imported inside the factory rather than
at module scope so the test suite - which has no reason to install an agent SDK
to check a payment rail - keeps running without it.

Run:  python -m agent.strands_buyer "restock the stationery cupboard"
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

GATEWAY = os.getenv("POCKETCHANGE_GATEWAY", "http://localhost:8080")
DEMO_TOKEN = os.getenv("POCKETCHANGE_DEMO_TOKEN", "")
TIMEOUT = 30.0

SYSTEM = """\
You buy things on a person's behalf through a payment gateway that enforces its
own limits.

You do not decide what you are allowed to spend. A signed mandate already does,
the gateway checks it on every call, and no wording you choose will change it.
If a payment is refused, read the reason and adapt the purchase - a smaller
cart is sometimes a real answer, arguing is never one.

If a payment comes back needing approval, stop and say so. A person is being
asked, and waiting is the correct behaviour rather than a failure.

Be specific about what you are buying and why. That text is recorded and read.
"""


def _headers(token: str) -> dict[str, str]:
    head = {"Content-Type": "application/json", "X-AIP-Token": token}
    if DEMO_TOKEN:
        # Gates writes so a crawler cannot drain a shared free tier. A brake,
        # not authentication - it ships inside a page anyone can read.
        head["X-Demo-Token"] = DEMO_TOKEN
    return head


def open_mandate(purpose: str, budget_rupees: int, *, gateway: str = GATEWAY) -> dict[str, Any]:
    """Mint the mandate. Deliberately NOT one of the agent's tools.

    The ceiling is the one decision that cannot be delegated to the thing being
    constrained by it. An agent that could open its own mandate could grant
    itself whatever it liked, and every guarantee downstream would be theatre.
    A person calls this; the agent receives the result.
    """
    r = httpx.post(
        f"{gateway}/mandates",
        json={
            "budget_paise": budget_rupees * 100,
            "purpose": purpose,
            "ttl_seconds": 3600,
        },
        # The person's credential, which is what makes this the person's call.
        headers={"X-Operator-Token": os.environ.get("POCKETCHANGE_OPERATOR_TOKEN", "")},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def make_tools(token: str, *, gateway: str = GATEWAY):
    """The two things the agent may do, as Strands tools."""
    from strands import tool

    @tool
    def check_budget() -> str:
        """How much of the authorised budget is left, in rupees."""
        mandate_id = json.loads(os.environ.get("_PC_MANDATE", "{}")).get("mandate_id", "")
        r = httpx.get(f"{gateway}/mandates/{mandate_id}", timeout=TIMEOUT)
        if r.status_code != 200:
            return f"could not read the mandate: {r.status_code}"
        body = r.json()
        left = (body["cap_paise"] - body["committed_paise"]) / 100
        return f"{left:,.0f} rupees remain of {body['cap_paise'] / 100:,.0f}"

    @tool
    def pay(amount_rupees: int, items: str, why: str) -> str:
        """Pay for a cart.

        Args:
            amount_rupees: total to pay, in rupees.
            items: what is being bought, as "sku:quantity" pairs separated by commas.
            why: one sentence on why this purchase matches what was authorised.
        """
        cart: dict[str, int] = {}
        for part in items.split(","):
            if ":" not in part:
                continue
            sku, _, qty = part.partition(":")
            cart[sku.strip()] = int(qty.strip() or 1)
        if not cart:
            return "no items parsed; pass them as 'SKU:quantity, SKU:quantity'"

        r = httpx.post(
            f"{gateway}/pay",
            headers=_headers(token),
            json={
                "amount_paise": amount_rupees * 100,
                "cart": cart,
                "context": why,
            },
            timeout=TIMEOUT,
        )

        # Each of these is a different fact and the agent is told which. A
        # refusal reported as a generic error is one an agent will retry
        # forever; a held payment reported as a failure is one it will try to
        # route around, which is the last thing anyone wants it doing.
        if r.status_code == 200:
            body = r.json()
            if body.get("replayed"):
                return (f"already paid - this exact cart at this exact price was "
                        f"bought already, order {body['order_id']}. Not charged twice.")
            return (f"paid {body['amount_paise'] / 100:,.0f} rupees, order "
                    f"{body['order_id']}. {body['remaining_paise'] / 100:,.0f} remain.")
        if r.status_code == 202:
            return ("held for a person to approve. Stop here and report that - "
                    "do not retry and do not restructure the purchase to avoid it.")
        if r.status_code == 402:
            d = r.json().get("detail", {})
            return (f"refused: not enough budget. {d.get('available', 0) / 100:,.0f} "
                    "rupees available. A smaller cart may work.")
        if r.status_code == 403:
            return ("refused: this token does not carry that authority. Nothing "
                    "you can buy will change that - report it and stop.")
        return f"refused ({r.status_code}): {r.text[:200]}"

    return [check_budget, pay]


def build(token: str, *, gateway: str = GATEWAY, model: str | None = None):
    """A Strands agent holding nothing but a token."""
    from strands import Agent

    kwargs: dict[str, Any] = {
        "system_prompt": SYSTEM,
        "tools": make_tools(token, gateway=gateway),
    }
    if model:
        kwargs["model"] = model
    return Agent(**kwargs)


def main(argv: list[str] | None = None) -> int:
    import sys

    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(__doc__)
        return 2

    task = " ".join(args)
    budget = int(os.getenv("POCKETCHANGE_BUDGET_RUPEES", "5000"))

    print(f"\n  gateway  {GATEWAY}")
    print(f"  task     {task}")
    print(f"  ceiling  {budget:,} rupees  (signed by a person, not by the agent)\n")

    mandate = open_mandate(task, budget)
    os.environ["_PC_MANDATE"] = json.dumps({"mandate_id": mandate["mandate_id"]})

    agent = build(mandate["token"])
    result = agent(task)
    print(f"\n{result}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
