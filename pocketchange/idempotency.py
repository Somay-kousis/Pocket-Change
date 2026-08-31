"""Idempotency key derivation and in-TTL replay detection.

AIP's second acknowledged gap. Its threat model lists "real-time replay within
TTL" as not addressed, and defers it to the transport layer - reasonable for a
token spec, useless for a payment system, because a replayed payment inside the
token's lifetime is indistinguishable from a legitimate one at the signature
layer. The token really is valid. It is *supposed* to authorise a payment. It
just already did.

Razorpay does not close this for us either. It offers idempotency on payouts
(X-Payout-Idempotency), transfers and refunds, but there is no documented
idempotency header on Orders creation - which is exactly the endpoint a checkout
uses. So this layer is not defence in depth. On the order path it is the only
defence there is.

The fingerprint covers the cart AND the amount. It once covered only the cart,
which meant the same basket at a different price hashed identical and the second
call was handed the first receipt - a price change disappearing in silence.

What remains after that is narrower and cannot be fixed by hashing harder: an
honest repurchase of the same cart at the same price inside the TTL is, byte for
byte, a retry. Nothing in the request distinguishes them. That is an
authorisation question rather than a fingerprinting one, and it is settled in
the gateway - see `next_occurrence` and PayRequest.repurchase.

Two halves:
  derive_key()  turns "what is being attempted" into a stable fingerprint
  ReplayStore   remembers what a key already returned, so a repeat replays the
                original response instead of doing the work again
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# The longest any mandate may live. /mandates refuses a longer ttl, and every
# delegated child is bounded by its parent's expiry, so no token outlives this.
MAX_MANDATE_LIFETIME = timedelta(hours=24)

# Must cover the longest-lived token, not a convenient hour. It was one hour
# while mandates lived up to 24, and the gap was a double charge: the same cart
# sent again after the window found no replay record, reached the rail a second
# time, and only then hit the settled reservation in the ledger and returned 500.
# The margin absorbs clock skew between minting and the check.
DEFAULT_TTL = MAX_MANDATE_LIFETIME + timedelta(minutes=5)


def canonical(payload: Any) -> str:
    """Stable JSON: sorted keys, no incidental whitespace.

    Two dicts that mean the same thing must produce the same string, or the
    fingerprint changes when nothing real did and the replay sails through.
    Python preserves insertion order, so {"a":1,"b":2} and {"b":2,"a":1} would
    otherwise serialise differently. sort_keys removes that.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def derive_key(*, mandate_id: str, tool: str, payload: Any) -> str:
    """Fingerprint one intended action.

    Deliberately derived from the *request*, never from a client-supplied id.
    If the agent chose its own key it could defeat replay protection by simply
    choosing a fresh one - and the agent is the component we assume is
    compromised.

    The mandate is included so two different people buying the identical cart
    do not collide with each other.
    """
    material = canonical({"mandate": mandate_id, "tool": tool, "payload": payload})
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class Replay:
    """A previously completed action, returned instead of repeating it."""

    key: str
    result: Any
    first_seen: datetime

    @property
    def age(self) -> timedelta:
        return datetime.now(timezone.utc) - self.first_seen


class ReplayStore:
    """Remembers completed actions for a window.

    Entries expire because the point is to catch a replay *inside the token's
    lifetime*. Once the token itself has expired the signature layer refuses the
    request anyway, so keeping the record longer buys nothing and grows forever.
    """

    def __init__(self, ttl: timedelta = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._seen: dict[str, Replay] = {}

    def get(self, key: str) -> Replay | None:
        """The prior result for this key, or None if this is genuinely new."""
        with self._lock:
            self._evict()
            return self._seen.get(key)

    def next_occurrence(self, base_key: str) -> int:
        """How many times this exact action has already been paid for.

        A deliberate repeat purchase cannot be told apart from a retry by
        looking at the request - the cart and the amount are identical, which is
        the whole difficulty. Something has to number the repeats, and it cannot
        be the caller: an agent that supplied its own occurrence would be
        choosing its own idempotency key, which is exactly what `derive_key`
        exists to refuse.

        So the number is counted here, from payments this gateway actually
        settled. The first repeat is occurrence 1, and its key is
        `<base>#1`. Nothing an agent can send changes the answer.

        Counting only survivors of the TTL is correct rather than convenient:
        once the original has expired there is no replay left to be confused
        with, so the disambiguation is not needed any more.
        """
        with self._lock:
            self._evict()
            prefix = f"{base_key}#"
            return 1 + sum(1 for k in self._seen if k.startswith(prefix))

    def record(self, key: str, result: Any) -> Replay:
        """Remember a completed action.

        First writer wins. If a key is somehow recorded twice the original
        result stands, because that is the answer the first caller already
        received and a replay must be told the same thing.
        """
        with self._lock:
            self._evict()
            existing = self._seen.get(key)
            if existing is not None:
                return existing
            entry = Replay(key=key, result=result, first_seen=datetime.now(timezone.utc))
            self._seen[key] = entry
            return entry

    def forget(self, key: str) -> None:
        """Drop a key so the action can be attempted again.

        Used when a payment fails. A charge that never happened must stay
        retryable; only success is permanent.
        """
        with self._lock:
            self._seen.pop(key, None)

    def _evict(self) -> None:
        """Called with the lock held."""
        cutoff = datetime.now(timezone.utc) - self._ttl
        stale = [k for k, v in self._seen.items() if v.first_seen < cutoff]
        for k in stale:
            del self._seen[k]

    def __len__(self) -> int:
        with self._lock:
            self._evict()
            return len(self._seen)
