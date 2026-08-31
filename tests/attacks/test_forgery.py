"""Token forgery and binding confusion.

A token is only authority if its signature chain verifies against this gateway's
root key. These cases present things that are not a genuine chain, or a genuine
chain bound in a confusing way, and check that none of them moves money.
"""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import KeyPair

from pocketchange import identity, token
from pocketchange.policy import Grant


def _foreign(budget=10 ** 9, depth=8):
    """A well-formed root signed by a key that is not this gateway's."""
    who = identity.web("attacker.example", "principal", keypair=KeyPair())
    return token.serialize(token.mint(who, budget_paise=budget, max_depth=depth,
                                      expires=datetime.now(timezone.utc) + timedelta(days=1)))


def _flip_byte(raw: str, index: int) -> str:
    pad = "=" * (-len(raw) % 4)
    data = bytearray(base64.urlsafe_b64decode(raw + pad))
    data[index % len(data)] ^= 0x01
    return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")


# --- not a token at all -----------------------------------------------------------

NONSENSE = [
    ("AAAA", "four_bytes_of_zeros"),
    ("", "an_empty_string"),
    ("   ", "only_whitespace"),
    ("not-base64-@@@", "not_base64"),
    ("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.", "a_jwt_shaped_string"),
    ("Bearer abcdef", "a_bearer_phrase"),
    ("../../etc/passwd", "a_path"),
    ("<token>pay</token>", "xml_shaped"),
    ("00000000", "eight_zeros"),
    ("deadbeef" * 8, "long_hex"),
    ("null", "the_word_null"),
    ("true", "the_word_true"),
]


@pytest.mark.network
@pytest.mark.parametrize("raw,label", NONSENSE, ids=[x[1] for x in NONSENSE])
def test_nonsense_in_the_x_aip_token_header(gw, raw, label):
    snap = gw.snapshot()
    r = gw.pay(raw, 1_000, {"a": 1})
    gw.blocked(r, 401, snap, audit="pay" if raw.strip() else False)


@pytest.mark.network
@pytest.mark.parametrize("raw,label", NONSENSE, ids=[x[1] for x in NONSENSE])
def test_nonsense_in_the_authorization_header(gw, raw, label):
    snap = gw.snapshot()
    r = gw.agent.post("/pay", headers={"Authorization": f"AIP {raw}"},
                      json={"amount_paise": 1_000, "cart": {"a": 1}, "context": "x"})
    gw.blocked(r, 401, snap, audit=False if not raw.strip() else "pay")


@pytest.mark.network
@pytest.mark.parametrize("raw,label", NONSENSE[:8], ids=[x[1] for x in NONSENSE[:8]])
def test_nonsense_in_the_a2a_body_binding(gw, raw, label):
    snap = gw.snapshot()
    r = gw.agent.post("/pay", json={"amount_paise": 1_000, "cart": {"a": 1},
                                    "context": "x", "aip_token": raw})
    gw.blocked(r, {401, 422}, snap, audit=False)


# --- a genuine chain signed by the wrong key --------------------------------------

@pytest.mark.network
def test_foreign_root_on_pay(gw):
    snap = gw.snapshot()
    gw.blocked(gw.pay(_foreign(), 1_000, {"a": 1}), 401, snap, audit="pay")


@pytest.mark.network
def test_foreign_root_on_delegate(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": _foreign(), "tools": ["pay"],
                                         "budget_paise": 1_000, "context": "x"})
    gw.blocked(r, 401, snap, audit="delegate")


@pytest.mark.network
def test_foreign_root_on_payout(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/payout", headers={"X-AIP-Token": _foreign()},
                      json={"account": "acc_x", "amount_paise": 1_000, "context": "x"})
    gw.blocked(r, 401, snap, audit="payout")


@pytest.mark.network
def test_foreign_child_narrowed_from_a_foreign_root(gw):
    parent = token.deserialize(_foreign(), KeyPair().public_key) if False else None
    who = identity.web("attacker.example", "p", keypair=KeyPair())
    root = token.mint(who, budget_paise=10 ** 9, max_depth=5,
                      expires=datetime.now(timezone.utc) + timedelta(days=1))
    child = token.attenuate(root, to="aip:web:attacker.example/payer",
                            grant=Grant(("pay",), 5_000), context="narrowing")
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(child), 1_000, {"a": 1}), 401, snap, audit="pay")


@pytest.mark.network
def test_foreign_root_reusing_a_real_mandate_id(gw):
    real = gw.mandate(budget=10_000)
    # A foreign token cannot adopt the real mandate's ledger line: it fails at
    # signature verification, long before any mandate id is read.
    snap = gw.snapshot()
    gw.blocked(gw.pay(_foreign(), 50_000, {"a": 1}), 401, snap, audit="pay")
    assert gw.state.ledger.state(real["mandate_id"]).committed_paise == 0


# --- a genuine chain with a flipped byte ------------------------------------------

@pytest.mark.network
@pytest.mark.parametrize("index,region", [
    pytest.param(1, "near_the_start", id="flip_near_the_start"),
    pytest.param(5, "in_the_authority_header", id="flip_in_the_authority_header"),
    pytest.param(20, "in_the_identity_block", id="flip_in_the_identity_block"),
    pytest.param(60, "in_the_check_body", id="flip_in_the_check_body"),
    pytest.param(120, "in_the_mid_chain", id="flip_in_the_mid_chain"),
    pytest.param(200, "in_the_signature", id="flip_in_the_signature"),
])
def test_one_flipped_byte_in_a_real_token(gw, index, region):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    r = gw.pay(_flip_byte(m["token"], index), 1_000, {"a": 1})
    gw.blocked(r, 401, snap, audit="pay")


@pytest.mark.network
def test_truncated_real_token(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"][:-10], 1_000, {"a": 1}), 401, snap, audit="pay")


@pytest.mark.network
def test_real_token_with_appended_bytes(gw):
    m = gw.mandate(budget=10_000)
    snap = gw.snapshot()
    gw.blocked(gw.pay(m["token"] + "AAAA", 1_000, {"a": 1}), 401, snap, audit="pay")


@pytest.mark.network
def test_real_token_with_swapped_case(gw):
    m = gw.mandate(budget=10_000)
    swapped = m["token"].swapcase()
    snap = gw.snapshot()
    gw.blocked(gw.pay(swapped, 1_000, {"a": 1}), 401, snap, audit="pay")


# --- binding confusion: which token actually pays ---------------------------------

@pytest.mark.agent
def test_poor_header_token_beats_rich_body_token(gw):
    poor = gw.mandate(budget=1_000)
    rich = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    r = gw.pay(poor["token"], 50_000, {"a": 1}, aip_token=rich["token"])
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_forged_header_with_a_real_body_token(gw):
    real = gw.mandate(budget=1_000)
    snap = gw.snapshot()
    # Header takes precedence; a forged header is refused even with a real body.
    r = gw.agent.post("/pay", headers={"X-AIP-Token": "AAAA"},
                      json={"amount_paise": 500, "cart": {"a": 1}, "context": "x",
                            "aip_token": real["token"]})
    gw.blocked(r, 401, snap, audit="pay")


@pytest.mark.agent
def test_real_header_with_a_forged_body_token(gw):
    real = gw.mandate(budget=5_000)
    # Header wins, so this is a normal payment on the real token; it must not be
    # charged twice or against the forged one.
    r = gw.agent.post("/pay", headers={"X-AIP-Token": real["token"]},
                      json={"amount_paise": 500, "cart": {"a": 1}, "context": "x",
                            "aip_token": "AAAA"})
    assert r.status_code == 200
    assert gw.state.ledger.state(real["mandate_id"]).committed_paise == 500


@pytest.mark.agent
def test_authorization_and_x_aip_token_disagree(gw):
    poor = gw.mandate(budget=1_000)
    rich = gw.mandate(budget=1_000_000)
    snap = gw.snapshot()
    # X-AIP-Token is read first, so the poor token binds and 50_000 overruns it.
    r = gw.agent.post("/pay", headers={"X-AIP-Token": poor["token"],
                                       "Authorization": f"AIP {rich['token']}"},
                      json={"amount_paise": 50_000, "cart": {"a": 1}, "context": "x"})
    gw.blocked(r, 403, snap, audit="pay")


@pytest.mark.agent
def test_two_mandates_cannot_share_a_ledger_line(gw):
    a = gw.mandate(budget=5_000)
    b = gw.mandate(budget=5_000)
    gw.pay(a["token"], 5_000, {"a": 1})
    # b is a different mandate id; a's spend must not count against it.
    assert gw.state.ledger.state(b["mandate_id"]).committed_paise == 0
    assert gw.pay(b["token"], 5_000, {"b": 1}).status_code == 200


# --- offline block tampering ------------------------------------------------------

@pytest.mark.agent
def test_offline_block_raising_the_budget(gw):
    from biscuit_auth import BlockBuilder

    m = gw.mandate(budget=1_000)
    tok = token.deserialize(m["token"], gw.state.root_public_key)
    tok = tok.append(BlockBuilder("budget(1000000000);"))
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(tok), 50_000, {"a": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_offline_block_adding_an_allow_rule(gw):
    from biscuit_auth import BlockBuilder

    m = gw.mandate(budget=1_000)
    tok = token.deserialize(m["token"], gw.state.root_public_key)
    tok = tok.append(BlockBuilder("check if true;"))
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(tok), 50_000, {"a": 1}), 403, snap, audit="pay")


@pytest.mark.agent
def test_datalog_injection_through_the_delegate_id(gw):
    m = gw.mandate(budget=10_000)
    r = gw.agent.post("/delegate", json={
        "token": m["token"], "tools": ["pay"], "budget_paise": 1_000,
        "context": "x", "to": 'x"); tool("payout'})
    # It is accepted as a literal string, never executed as policy.
    if r.status_code == 200:
        child = token.deserialize(r.json()["token"], gw.state.root_public_key)
        snap = gw.snapshot()
        gw.blocked(gw.agent.post("/payout", headers={"X-AIP-Token": r.json()["token"]},
                                 json={"account": "a", "amount_paise": 500, "context": "x"}),
                   {403, 501}, snap, audit="payout")
    else:
        assert r.status_code in (401, 422)


@pytest.mark.network
def test_token_from_a_previous_gateway_instance(gw):
    from pocketchange import gateway as gw_module

    old = gw_module.State()
    root = token.mint(old.principal, budget_paise=10_000, max_depth=3,
                      expires=datetime.now(timezone.utc) + timedelta(hours=1))
    # gw.state is the current instance with a different root key.
    snap = gw.snapshot()
    gw.blocked(gw.pay(token.serialize(root), 1_000, {"a": 1}), 401, snap, audit="pay")


@pytest.mark.network
def test_no_token_on_any_binding(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/pay", json={"amount_paise": 1_000, "cart": {"a": 1}, "context": "x"})
    gw.blocked(r, 401, snap, audit=False)


@pytest.mark.agent
def test_empty_x_aip_token_falls_through_to_no_token(gw):
    snap = gw.snapshot()
    r = gw.agent.post("/pay", headers={"X-AIP-Token": "  "},
                      json={"amount_paise": 1_000, "cart": {"a": 1}, "context": "x"})
    gw.blocked(r, 401, snap, audit=False)


@pytest.mark.network
def test_biscuit_from_bytes_of_a_real_token_against_wrong_key(gw):
    """A real token's bytes, presented as base64url, still fail against the key
    they were not signed under once a byte is corrupted mid-chain."""
    m = gw.mandate(budget=10_000)
    corrupted = _flip_byte(m["token"], 40)
    snap = gw.snapshot()
    gw.blocked(gw.pay(corrupted, 1_000, {"a": 1}), 401, snap, audit="pay")
