"""The `pocketchange` command.

`pyproject.toml` has declared this entry point since day two and the module did
not exist, so the installed command was broken. It does the things a person needs
to do by hand: see what is waiting on them, answer it, and inspect a mandate.

Approvals are the reason this exists. A monitor that escalates to a human needs
somewhere for the human to be.

  pocketchange approvals            what is waiting for a decision
  pocketchange approve <id> [note]  release a suspended payment
  pocketchange deny <id> [note]     refuse it and give the budget back
                                    (both need POCKETCHANGE_OPERATOR_TOKEN set)
  pocketchange mandate <id>         what a mandate has spent
  pocketchange watch                the funnel, live, as it runs
  pocketchange audit                the trail, denials included
  pocketchange vectors              SoK coverage register
  pocketchange serve                run the gateway
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

DEFAULT_URL = "http://localhost:8080"
RUPEE = 100


def _client(url: str) -> httpx.Client:
    return httpx.Client(base_url=url, timeout=15.0)


def _operator_headers() -> dict[str, str]:
    """The operator credential, plus the demo token if this gateway gates writes.

    Read from the environment, never a flag, so it does not land in shell history.
    """
    headers = {}
    operator = os.environ.get("POCKETCHANGE_OPERATOR_TOKEN", "").strip()
    if operator:
        headers["X-Operator-Token"] = operator
    demo = os.environ.get("POCKETCHANGE_DEMO_TOKEN", "").strip()
    if demo:
        headers["X-Demo-Token"] = demo
    return headers


def _rupees(paise: int | None) -> str:
    return "-" if paise is None else f"Rs {paise / RUPEE:,.2f}"


def _unreachable(url: str) -> int:
    print(f"  no gateway at {url}\n  start one with:  pocketchange serve", file=sys.stderr)
    return 2


def approvals(url: str) -> int:
    try:
        with _client(url) as client:
            pending = client.get("/approvals").json()["pending"]
    except httpx.HTTPError:
        return _unreachable(url)

    if not pending:
        print("\n  nothing waiting.\n")
        return 0

    print(f"\n  {len(pending)} payment(s) waiting on you\n")
    for item in pending:
        print(f"  {item['approval_id']}   {_rupees(item['amount_paise'])}")
        print(f"    why escalated  {item['reason']}")
        print(f"    agent claims   {item['agent_claim'][:70]}")
        print(f"    cart           {item['cart']}")
        print(f"    expires        {item['expires_at'][11:19]}")
        print(f"    decide         pocketchange approve {item['approval_id']}")
        print(f"                   pocketchange deny {item['approval_id']}\n")
    return 0


def decide(url: str, approval_id: str, approve: bool, note: str) -> int:
    try:
        with _client(url) as client:
            response = client.post(
                f"/approvals/{approval_id}",
                json={"decision": "approve" if approve else "deny",
                      "by": "cli", "note": note},
                headers=_operator_headers(),
            )
    except httpx.HTTPError:
        return _unreachable(url)

    body = response.json()
    if response.status_code >= 400:
        print(f"  refused: {body.get('detail', body)}", file=sys.stderr)
        if response.status_code in (401, 503) and "X-Operator-Token" not in _operator_headers():
            print("  set POCKETCHANGE_OPERATOR_TOKEN to the gateway's operator token",
                  file=sys.stderr)
        return 1
    if body["status"] == "approved":
        print(f"\n  approved. order {body['order_id']}, "
              f"{_rupees(body['remaining_paise'])} left on the mandate.\n")
    else:
        print("\n  denied. the reservation was released.\n")
    return 0


def mandate(url: str, mandate_id: str) -> int:
    try:
        with _client(url) as client:
            response = client.get(f"/mandates/{mandate_id}")
    except httpx.HTTPError:
        return _unreachable(url)
    if response.status_code == 404:
        print(f"  no mandate {mandate_id}", file=sys.stderr)
        return 1
    state = response.json()
    print(f"\n  cap        {_rupees(state['cap_paise'])}")
    print(f"  spent      {_rupees(state['committed_paise'])}")
    print(f"  held       {_rupees(state['reserved_paise'])}")
    print(f"  available  {_rupees(state['available_paise'])}\n")
    return 0


def audit(url: str) -> int:
    try:
        with _client(url) as client:
            trail = client.get("/audit").json()
    except httpx.HTTPError:
        return _unreachable(url)

    print(f"\n  {trail['count']} entries, chain intact: {trail['intact']}\n")
    for entry in trail["entries"]:
        mark = {"allowed": "ok ", "denied": "REF", "escalated": "ESC"}.get(
            entry["decision"], "?  "
        )
        amount = _rupees(entry["amount_paise"]) if entry["amount_paise"] else ""
        print(f"  {mark} {entry['seq']:>3}  {entry['tool']:<10} {amount:>14}  "
              f"{entry['reason'][:46]}")
    print()
    return 0


def vectors() -> int:
    from eval.vectors import report

    print(report())
    return 0


def serve(url: str) -> int:
    import uvicorn

    host, _, port = url.removeprefix("http://").partition(":")
    uvicorn.run("pocketchange.gateway:app", host=host or "127.0.0.1",
                port=int(port or 8080), reload=False)
    return 0


# --- watch -----------------------------------------------------------------
#
# "All logs show up." The funnel emits an event per node per transition and this
# tails them, indenting by depth so the tree draws itself as it is built.

GLYPH = {
    "spawned":    ("·", ""),
    "granted":    ("⊢", "\033[36m"),
    "decomposed": ("┬", "\033[36m"),
    "searching":  ("⌕", "\033[35m"),
    "paying":     ("→", ""),
    "allowed":    ("✓", "\033[32m"),
    "settled":    ("✓", "\033[32m"),
    "denied":     ("✗", "\033[31m"),
    "escalated":  ("!", "\033[33m"),
    "bound_hit":  ("■", "\033[33m"),
}
RESET = "\033[0m"
DIM = "\033[2m"


def _line(event: dict) -> str:
    kind = event.get("kind", "?")
    glyph, colour = GLYPH.get(kind, ("?", ""))
    detail = event.get("detail") or {}
    depth = event.get("depth", 0)

    # A bound that ended the recursion normally is not a fault, and colouring it
    # like one trains a reader to ignore the ones that are.
    if kind == "bound_hit" and not detail.get("fault"):
        colour = DIM

    note = ""
    if kind == "granted":
        note = f"{_rupees(detail.get('budget_paise'))}  [{','.join(detail.get('tools', []))}]"
    elif kind == "decomposed":
        note = f"into {detail.get('children')} · allocated {_rupees(detail.get('allocated'))}"
    elif kind == "spawned":
        note = str(detail.get("description", ""))[:56]
        if detail.get("sourcing") == "best":
            note += "  ⌕ web"
        elif detail.get("supplier"):
            note += f"  → {detail['supplier']}"
    elif kind == "paying":
        note = _rupees(detail.get("amount_paise"))
    elif kind in ("denied", "bound_hit"):
        note = str(detail.get("reason", ""))[:60]
    elif kind == "settled":
        note = str(detail.get("result", ""))[:60]

    at = str(event.get("at", ""))[11:19]
    indent = "  " * depth
    node = event.get("node_id", "?")
    return (f"{DIM}{at}{RESET} {indent}{colour}{glyph}{RESET} "
            f"{node:<18} {colour}{kind:<11}{RESET} {note}")


def watch(url: str, *, replay: bool = True) -> int:
    """Tail the gateway's event stream until interrupted."""
    print(f"\n  watching {url}/stream — ctrl-c to stop\n")
    try:
        with httpx.Client(base_url=url, timeout=None) as client:
            with client.stream("GET", "/stream", params={"replay": replay}) as response:
                if response.status_code != 200:
                    print(f"  gateway returned {response.status_code}", file=sys.stderr)
                    return 1
                for raw in response.iter_lines():
                    if not raw.startswith("data: "):
                        continue      # comments and the event: line
                    try:
                        print(_line(json.loads(raw[6:])))
                    except json.JSONDecodeError:
                        continue
    except httpx.HTTPError:
        return _unreachable(url)
    except KeyboardInterrupt:
        print("\n  stopped.\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pocketchange", description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help=f"gateway URL (default {DEFAULT_URL})")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("approvals", help="payments waiting on a decision")
    for name, helptext in (("approve", "release a suspended payment"),
                           ("deny", "refuse it and release the budget")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("approval_id")
        p.add_argument("note", nargs="?", default="")
    p = sub.add_parser("mandate", help="what a mandate has spent")
    p.add_argument("mandate_id")
    w = sub.add_parser("watch", help="the funnel, live, as it runs")
    w.add_argument("--no-replay", action="store_true",
                   help="only new events; skip the buffered history")
    sub.add_parser("audit", help="the audit trail, denials included")
    sub.add_parser("vectors", help="SoK coverage register")
    sub.add_parser("serve", help="run the gateway")

    args = parser.parse_args(argv)
    if args.command == "approvals":
        return approvals(args.url)
    if args.command in ("approve", "deny"):
        return decide(args.url, args.approval_id, args.command == "approve", args.note)
    if args.command == "mandate":
        return mandate(args.url, args.mandate_id)
    if args.command == "watch":
        return watch(args.url, replay=not args.no_replay)
    if args.command == "audit":
        return audit(args.url)
    if args.command == "vectors":
        return vectors()
    if args.command == "serve":
        return serve(args.url)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
