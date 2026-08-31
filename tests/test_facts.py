"""The landing page reads what the system is, instead of being told.

Its headline numbers were typed into the HTML and went three releases stale: 258
tests against 372, 9 of 12 SoK vectors against 10, and an enforcement figure that
only ever held for the in-memory ledger while the console beside it showed
something twenty times larger. Each drifted because a person had to remember.
"""

import pathlib
import re

import pytest
from fastapi.testclient import TestClient

from tests._operator import OPERATOR_HEADERS

from pocketchange import funnel, gateway
from pocketchange.monitor import Verdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / "frontend" / "index.html"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    gateway.state = gateway.State()
    return TestClient(gateway.app, headers=OPERATOR_HEADERS)


def test_facts_derives_the_bound_count_rather_than_stating_it():
    """Adding a bound to funnel.Bounds must change the front page without
    anyone editing the front page."""
    from fastapi.testclient import TestClient as TC

    body = TC(gateway.app).get("/facts").json()
    assert body["bounds"] == len(funnel.Bounds.__dataclass_fields__) + 2


def test_facts_reports_the_real_sok_coverage(client):
    from eval.vectors import VECTORS, applicable

    sok = client.get("/facts").json()["sok"]
    assert sok == {"defended": len(applicable()), "total": len(VECTORS)}


def test_facts_lists_every_verdict_that_exists(client):
    """`defer` was in this enum and unhandled for most of the project's life.
    If a fourth is ever added, the page should say so on its own."""
    assert client.get("/facts").json()["verdicts"] == [v.value for v in Verdict]


def test_facts_says_which_rail_is_actually_in_use(client):
    assert client.get("/facts").json()["rail"] == "fake"      # no keys in tests


def test_facts_survives_a_broken_store(client, monkeypatch):
    """The front page must not fail to render because a counter is unavailable."""
    class Broken:
        def all(self):
            raise RuntimeError("firestore unreachable")

    monkeypatch.setattr(gateway.state, "counterparties", Broken())
    body = client.get("/facts").json()
    assert body["bounds"] and "counterparties" not in body["live"]


# --- the one number that cannot be derived ---------------------------------


def test_the_landing_page_test_count_matches_reality(request):
    """`tests offline` is a fact about this repository, not about the running
    system, so /facts cannot supply it. This turns silent drift into a failure."""
    claimed = re.search(r'id="stat-tests">(\d+)<', INDEX.read_text())
    assert claimed, "the landing page no longer states a test count"

    actual = request.session.testscollected
    assert int(claimed.group(1)) == actual, (
        f"the landing page claims {claimed.group(1)} tests; there are {actual}. "
        "Update frontend/index.html."
    )


# --- the console must ask for a path the deployment actually answers --------

GATEWAY_JS = ROOT / "frontend" / "gateway.js"


def test_the_console_health_check_avoids_the_edge_intercepted_path():
    """Google's edge answers /healthz with its own 404 before the request
    reaches the container, so a console that polls it concludes there is no
    gateway and shows "No gateway at " on a service that is perfectly healthy.

    That is exactly what shipped: the backend grew /status as the alias, the
    console was never moved across, and the deployed page told every visitor
    the system was down. Both routes share one handler, so /status is correct
    locally too and there is no reason to name the other one here.
    """
    source = GATEWAY_JS.read_text()
    health = re.search(r"export const health\s*=\s*\(\)\s*=>\s*json\('([^']+)'\)",
                       source)
    assert health, "frontend/gateway.js no longer exports a health check"
    assert health.group(1) == "/status", (
        f"the console polls {health.group(1)}; Cloud Run's edge intercepts "
        "/healthz, so the health check must use /status."
    )
