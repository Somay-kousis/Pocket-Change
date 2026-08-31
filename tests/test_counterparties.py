"""Our own record of who we have paid.

Everything the buyer knows about a supplier today comes from the supplier.
`merchant/sellers.py` derives `is_established` from `trading_months` and
`review_count`, both of which sit in the seller's own record, and a hostile one
writes whatever it likes there. This is the counter-evidence: written by the
gateway from payments that actually cleared.
"""

import pytest
from datetime import datetime, timezone

from pocketchange.counterparties import (
    Counterparty, InMemoryCounterparties, NEW, UNKNOWN, from_env)


@pytest.fixture
def book():
    return InMemoryCounterparties()


def test_an_unknown_party_has_no_record(book):
    assert book.lookup("meridian-systems") is None


def test_a_record_describes_prior_dealings_never_their_absence(book):
    """A record exists only because something cleared. The never-dealt-with case
    is a MISSING row - conflating the two made a supplier we had already paid
    keep reading as unknown to the monitor."""
    row = book.record("meridian-systems", amount_paise=50_000, mandate_id="m1")
    assert row.orders == 1
    assert row.only_once
    assert row.describe() == "paid once before, 500 rupees"
    assert "never" not in row.describe()


def test_history_accumulates_across_payments(book):
    for _ in range(4):
        row = book.record("meridian-systems", amount_paise=25_000, mandate_id="m1")
    assert row.orders == 4
    assert row.total_paise == 100_000
    assert not row.only_once
    assert "paid 4 times" in row.describe()


def test_distinct_mandates_are_counted_once_each(book):
    book.record("apex", amount_paise=10, mandate_id="m1")
    book.record("apex", amount_paise=10, mandate_id="m1")
    row = book.record("apex", amount_paise=10, mandate_id="m2")
    assert row.orders == 3
    assert row.mandates == 2


def test_parties_are_kept_apart(book):
    book.record("apex", amount_paise=10, mandate_id="m1")
    book.record("northgate", amount_paise=99, mandate_id="m1")
    assert book.lookup("apex").total_paise == 10
    assert book.lookup("northgate").total_paise == 99
    assert len(book.all()) == 2


def test_a_nameless_counterparty_is_refused(book):
    for blank in ("", "   "):
        with pytest.raises(ValueError):
            book.record(blank, amount_paise=1, mandate_id="m1")


def test_without_a_project_it_stays_in_memory(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert isinstance(from_env(), InMemoryCounterparties)


def test_the_record_cannot_be_written_from_outside_the_gateway():
    """The asymmetry that makes this worth having: a seller can inflate its own
    review count, and cannot touch this."""
    import inspect

    from pocketchange import gateway

    source = inspect.getsource(gateway)
    # Exactly one place writes it, and it is behind a settled payment.
    assert source.count("state.counterparties.record(") == 1
    assert "ledger_state = _commit(reservation_id)" in source


# --- how it went, not just that it happened ---------------------------------


def test_a_tally_alone_is_not_a_reputation(book):
    """Forty orders beside five escalations and two human refusals is a WORSE
    record than no history. A summary reporting only the forty would reproduce
    the sybil problem one level up."""
    for _ in range(40):
        book.record("bestdeals", amount_paise=1_000, mandate_id="m1")
    for _ in range(5):
        book.flag("bestdeals", "escalated")
    book.flag("bestdeals", "vetoed")
    book.flag("bestdeals", "vetoed")

    row = book.lookup("bestdeals")
    assert row.orders == 40 and row.trouble == 7
    line = row.describe()
    # Trouble leads, so a long tally cannot be used as cover.
    assert line.startswith("CONCERNS")
    assert line.index("refused by a person") < line.index("paid 40 times")


def test_a_flag_needs_no_payment_behind_it(book):
    """A supplier whose pages carry injected instructions has a record with us
    even though we never paid them - and that record is worth more than none."""
    book.flag("bestdeals", "injections")
    row = book.lookup("bestdeals")
    assert row.orders == 0
    assert row.injections == 1
    assert "never paid" in row.describe()


def test_paying_a_flagged_party_does_not_wash_the_flags_away(book):
    """record() once rebuilt the row from scratch and dropped every flag, so a
    party we had caught injecting became clean the moment they were paid."""
    book.flag("apex", "injections")
    book.flag("apex", "vetoed")
    book.record("apex", amount_paise=5_000, mandate_id="m1")

    row = book.lookup("apex")
    assert row.orders == 1
    assert row.injections == 1 and row.vetoed == 1
    assert "CONCERNS" in row.describe()


def test_an_unknown_flag_is_refused(book):
    with pytest.raises(ValueError, match="unknown flag"):
        book.flag("apex", "vibes")


def test_a_clean_record_says_nothing_about_concerns(book):
    book.record("northgate", amount_paise=5_000, mandate_id="m1")
    assert "CONCERNS" not in book.lookup("northgate").describe()
