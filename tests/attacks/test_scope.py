"""Tool scope escalation.

Every delegation block says which tools its holder may use, and a child can only
narrow that. Since the mint-time fix, /delegate also refuses to mint a child
holding a tool its parent does not. The one tool no token is ever granted is
`payout`, so the endpoint that exists to tempt an injected agent always refuses.
"""

import pytest

from pocketchange import token
from pocketchange.policy import Grant


def _payout(gw, tok, account="acc_supplier_42", amount=1_000, **extra):
    return gw.agent.post("/payout", headers={"X-AIP-Token": tok}, json={
        "account": account, "amount_paise": amount, "context": "settle directly", **extra})


def _scoped(gw, tools, budget=10_000):
    m = gw.mandate()
    return gw.delegate(m["token"], tools=tools, budget=budget)


# --- payout, the tool nobody is ever granted --------------------------------------

@pytest.mark.agent
@pytest.mark.parametrize("tok_tools,label", [
    pytest.param(("pay",), "payout_from_a_pay_token", id="payout_from_a_pay_token"),
    pytest.param(("pay", "search"), "payout_from_a_pay_and_search_token",
                 id="payout_from_a_pay_and_search_token"),
    pytest.param(("delegate", "pay"), "payout_from_a_broker_token",
                 id="payout_from_a_broker_token"),
    pytest.param(("search", "cart"), "payout_from_a_shopper_token",
                 id="payout_from_a_shopper_token"),
])
def test_payout_is_refused_for_every_delegated_scope(gw, tok_tools, label):
    tok = _scoped(gw, tok_tools)
    snap = gw.snapshot()
    gw.blocked(_payout(gw, tok), {403, 501}, snap, audit="payout")


@pytest.mark.agent
def test_payout_from_the_root_mandate(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    gw.blocked(_payout(gw, m["token"]), {403, 501}, snap, audit="payout")


@pytest.mark.agent
def test_payout_through_the_a2a_binding(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/payout", json={"account": "acc_x", "amount_paise": 1_000,
                                       "context": "refund", "aip_token": m["token"]})
    gw.blocked(r, {403, 501}, snap, audit="payout")


@pytest.mark.agent
def test_payout_reached_from_a_pay_mandate_that_has_budget(gw):
    m = gw.mandate(budget=50_000)
    snap = gw.snapshot()
    gw.blocked(_payout(gw, m["token"], amount=40_000), {403, 501}, snap, audit="payout")


# --- delegating a tool the parent does not hold -----------------------------------

@pytest.mark.agent
@pytest.mark.parametrize("parent_tools,want", [
    pytest.param(("pay",), ["payout"], id="pay_token_delegates_payout"),
    pytest.param(("search", "cart"), ["pay"], id="shopper_delegates_pay"),
    pytest.param(("search",), ["cart"], id="search_token_delegates_cart"),
    pytest.param(("pay",), ["pay", "payout"], id="pay_token_delegates_pay_plus_payout"),
])
def test_cannot_delegate_a_tool_the_parent_lacks(gw, parent_tools, want):
    parent = _scoped(gw, ("delegate",) + parent_tools)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": parent, "tools": want,
                                         "budget_paise": 1_000, "context": "expanding"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_offline_block_adding_a_tool_does_not_grant_it(gw):
    """Appending `tool("payout")` facts offline cannot add a capability: the
    parent's `check if tool($t), [...].contains($t)` still has to pass."""
    m = gw.mandate()
    tok = token.deserialize(m["token"], gw.state.root_public_key)
    narrowed = token.attenuate(tok, to="aip:web:pocketchange.dev/payer/x",
                               grant=Grant(("pay",), 5_000), context="pay only")
    # Now try to use payout with this pay-only token.
    snap = gw.snapshot()
    gw.blocked(_payout(gw, token.serialize(narrowed)), {403, 501}, snap, audit="payout")


@pytest.mark.agent
def test_child_scoped_to_pay_cannot_be_used_to_delegate(gw):
    parent = _scoped(gw, ("delegate", "pay"))
    child = gw.delegate(parent, tools=("pay",), budget=3_000)
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": child, "tools": ["pay"],
                                         "budget_paise": 1_000, "context": "sub-sub"})
    gw.blocked(r, 403, snap, audit="delegate")


@pytest.mark.agent
def test_pay_with_a_delegate_only_token(gw):
    tok = _scoped(gw, ("delegate",))
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_pay_with_a_search_only_token(gw):
    tok = _scoped(gw, ("search",))
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000), 403, snap, audit="pay")


@pytest.mark.agent
def test_pay_with_a_cart_only_token(gw):
    tok = _scoped(gw, ("cart",))
    snap = gw.snapshot()
    gw.blocked(gw.pay(tok, 1_000), 403, snap, audit="pay")


@pytest.mark.agent
@pytest.mark.parametrize("tool_name", [
    pytest.param("transfer", id="invented_tool_transfer"),
    pytest.param("withdraw", id="invented_tool_withdraw"),
    pytest.param("admin", id="invented_tool_admin"),
    pytest.param("pay ", id="pay_with_a_trailing_space"),
    pytest.param("PAY", id="pay_in_capitals"),
])
def test_invented_tool_names_are_never_authorised(gw, tool_name):
    m = gw.mandate()
    tok = gw.delegate(m["token"], tools=("pay",), budget=5_000)
    from pocketchange.policy import Operation

    parsed = token.deserialize(tok, gw.state.root_public_key)
    with pytest.raises(token.Denied):
        token.verify(parsed, Operation(tool_name, 1_000, depth=1))


@pytest.mark.agent
def test_delegating_an_empty_tool_list(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"], "tools": [],
                                         "budget_paise": 1_000, "context": "nothing"})
    gw.blocked(r, 422, snap, audit=False)


@pytest.mark.agent
def test_delegating_more_tools_than_the_limit(gw):
    m = gw.mandate()
    snap = gw.snapshot()
    r = gw.agent.post("/delegate", json={"token": m["token"],
                                         "tools": [f"t{i}" for i in range(50)],
                                         "budget_paise": 1_000, "context": "many"})
    gw.blocked(r, 422, snap, audit=False)
