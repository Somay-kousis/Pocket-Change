"""Malformed and oversized input.

Hole 5: money fields accepted non-integers and values past i64. Hole 6: no
length limits anywhere. Also here: inputs that used to crash the reply itself (a
lone surrogate, a 2 MB echo) rather than return a clean refusal.

Every case is refused with a bounded reply, no rail order, and no spend.
"""

import pytest

from pocketchange import gateway


def _raw(gw, tok, body: bytes):
    return gw.agent.post("/pay", content=body,
                         headers={"X-AIP-Token": tok, "Content-Type": "application/json"})


def _small_reply(r):
    assert len(r.content) < 8_192, f"reply is {len(r.content)} bytes"


BAD_AMOUNTS = [
    (True, "amount_true"),
    (False, "amount_false"),
    ("100", "amount_numeric_string"),
    ("1e3", "amount_exponent_string"),
    ("0x64", "amount_hex_string"),
    (100.0, "amount_whole_float"),
    (99.5, "amount_fractional_float"),
    (-1, "amount_negative"),
    (0, "amount_zero"),
    (2 ** 63, "amount_past_signed_64_bit"),
    (2 ** 64 + 7, "amount_past_unsigned_64_bit"),
    (gateway.MAX_PAISE + 1, "amount_one_past_the_ceiling"),
    (None, "amount_null"),
    ([100], "amount_as_list"),
    ({"paise": 100}, "amount_as_object"),
]


@pytest.mark.agent
@pytest.mark.parametrize("value,label", BAD_AMOUNTS, ids=[x[1] for x in BAD_AMOUNTS])
def test_pay_amount_must_be_a_strict_bounded_integer(gw, value, label):
    m = gw.mandate(budget=100_000)
    snap = gw.snapshot()
    r = gw.pay(m["token"], value, {"STA-A4-5": 1})
    gw.blocked(r, 422, snap, audit=False)
    _small_reply(r)


@pytest.mark.agent
@pytest.mark.parametrize("value,label", BAD_AMOUNTS, ids=[x[1] for x in BAD_AMOUNTS])
def test_mandate_budget_must_be_a_strict_bounded_integer(gw, value, label):
    snap = gw.snapshot()
    r = gw.operator.post("/mandates", json={"budget_paise": value, "purpose": "x"})
    assert r.status_code == 422
    _small_reply(r)
    assert len(gw.state.ledger._mandates) == 0


@pytest.mark.agent
@pytest.mark.parametrize("value,label", BAD_AMOUNTS, ids=[x[1] for x in BAD_AMOUNTS])
def test_delegate_budget_must_be_a_strict_bounded_integer(gw, value, label):
    m = gw.mandate(budget=100_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": value, "context": "x"})
    # ge=0 means a literal integer 0 is a valid delegation; a bool is not an int.
    if type(value) is int and value == 0:
        assert r.status_code == 200
        return
    assert r.status_code in (403, 422)
    gw.unmoved(snap)
    _small_reply(r)


# --- oversized fields ----------------------------------------------------------

@pytest.mark.agent
def test_two_megabyte_context(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = _raw(gw, m["token"],
             b'{"amount_paise":5,"cart":{"a":1},"context":"' + b"x" * 2_000_000 + b'"}')
    gw.blocked(r, {413, 422}, snap, audit=False)
    _small_reply(r)


@pytest.mark.agent
def test_context_one_over_the_character_limit(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.pay(m["token"], 5, {"a": 1}, context="x" * (gateway.MAX_CONTEXT_CHARS + 1))
    gw.blocked(r, 422, snap, audit=False)


@pytest.mark.agent
def test_oversized_cart(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    cart = {f"sku{i}": i for i in range(5_000)}
    r = gw.pay(m["token"], 5, cart)
    gw.blocked(r, {413, 422}, snap, audit=False)


@pytest.mark.agent
def test_deeply_nested_cart(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    body = b'{"amount_paise":5,"context":"x","cart":' + b'{"a":' * 3_000 + b"1" + b"}" * 3_000 + b"}"
    r = _raw(gw, m["token"], body)
    gw.blocked(r, {413, 422}, snap, audit=False)
    _small_reply(r)


@pytest.mark.agent
def test_oversized_delegate_context(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": 10, "context": "x" * 5_000})
    gw.blocked(r, {413, 422}, snap, audit=False)


@pytest.mark.agent
def test_oversized_delegate_id(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": 10, "context": "x", "to": "a" * 5_000})
    gw.blocked(r, {413, 422}, snap, audit=False)


@pytest.mark.network
def test_oversized_token(gw):
    snap = gw.snapshot()
    r = gw.pay("A" * 100_000, 5, {"a": 1})
    gw.blocked(r, {401, 413}, snap, audit=False)
    _small_reply(r)


@pytest.mark.agent
def test_too_many_cart_keys_by_bytes(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    cart = {"k": "v" * 20_000}
    r = gw.pay(m["token"], 5, cart)
    gw.blocked(r, {413, 422}, snap, audit=False)


# --- inputs that used to crash the reply rather than refuse ---------------------

@pytest.mark.agent
def test_lone_surrogate_in_the_context(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    body = '{"amount_paise":5,"cart":{"a":1},"context":"buy \\ud800 now"}'.encode("utf-8")
    r = _raw(gw, m["token"], body)
    assert r.status_code != 500
    gw.unmoved(snap)
    _small_reply(r)


@pytest.mark.agent
def test_lone_surrogate_in_a_cart_key(gw):
    m = gw.mandate()
    r = _raw(gw, m["token"],
             '{"amount_paise":5,"cart":{"\\udfff":1},"context":"x"}'.encode("utf-8"))
    # A surrogate escapes to valid JSON, so this is a weird-but-valid cart; the
    # one thing it must never be is a 500 that leaves the reply unencodable.
    assert r.status_code != 500
    gw.state.audit.verify()


@pytest.mark.agent
@pytest.mark.parametrize("fragment,label", [
    (b"NaN", "nan"),
    (b"Infinity", "infinity"),
    (b"-Infinity", "negative_infinity"),
])
def test_non_finite_numbers_in_the_cart(gw, fragment, label):
    m = gw.mandate()
    snap = gw.snapshot()
    body = b'{"amount_paise":5,"context":"x","cart":{"a":' + fragment + b"}}"
    r = _raw(gw, m["token"], body)
    assert r.status_code != 500
    gw.unmoved(snap)


@pytest.mark.network
@pytest.mark.parametrize("body,label", [
    (b"", "empty_body"),
    (b"{", "unclosed_brace"),
    (b"[]", "a_bare_array"),
    (b"null", "a_bare_null"),
    (b"\xff\xfe\x00", "raw_bytes"),
    (b'{"amount_paise":5}', "missing_required_fields"),
])
def test_unparseable_bodies_are_refused_cleanly(gw, body, label):
    m = gw.mandate()
    snap = gw.snapshot()
    r = _raw(gw, m["token"], body)
    assert r.status_code in (400, 401, 422)
    gw.unmoved(snap)
    _small_reply(r)


@pytest.mark.agent
def test_unknown_field_is_rejected_not_ignored(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.pay(m["token"], 5, {"a": 1}, cap_override=10 ** 9)
    gw.blocked(r, 422, snap, audit=False)


@pytest.mark.agent
@pytest.mark.parametrize("ctx,label,status,aud", [
    ("", "empty_context", 422, False),
    ("   ", "whitespace_context", 400, "pay"),
    ("\t\n", "tab_and_newline_context", 400, "pay"),
])
def test_blank_context_on_pay(gw, ctx, label, status, aud):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.pay(m["token"], 5, {"a": 1}, context=ctx)
    gw.blocked(r, status, snap, audit=aud)


@pytest.mark.agent
@pytest.mark.parametrize("ctx,label,status,aud", [
    ("", "empty_context", 422, False),
    ("   ", "whitespace_context", 400, "delegate"),
])
def test_blank_context_on_delegate(gw, ctx, label, status, aud):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": ["pay"],
                                         "budget_paise": 10, "context": ctx})
    gw.blocked(r, status, snap, audit=aud)
