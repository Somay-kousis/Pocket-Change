"""Cumulative spend ledger and two-phase reservations.

This is the file the project exists for.

AIP's budget check asks "is this amount under the cap?" - a question about one
payment in isolation. It cannot ask "has the cap already been spent?", because a
token is a static document and knows nothing about history. The paper says so
outright: the verifier "does not track cumulative spend... Aggregate spend
enforcement is the runtime's responsibility, not the token's."

So an agent holding a valid 500-rupee mandate can spend 500 rupees, repeatedly,
forever, and every single payment verifies correctly. This module is what makes
that impossible.

Two-phase reservation, not a simple counter, because the gap between "check the
budget" and "charge the card" is where money is lost. Two concurrent payments
can both read a 900-rupee balance, both conclude 899 is affordable, and both
charge. Reserving inside a lock closes that window: the second request sees the
first one's reservation even though nothing has been charged yet.
"""

from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol


class LedgerError(Exception):
    """Base for everything this module refuses."""


class InsufficientBudget(LedgerError):
    """The mandate cannot cover this on top of what it has already spent.

    Carries the numbers so the audit trail and the dashboard can show the user
    exactly why, rather than a bare refusal.
    """

    def __init__(self, *, requested: int, available: int, cap: int, committed: int, reserved: int):
        self.requested = requested
        self.available = available
        self.cap = cap
        self.committed = committed
        self.reserved = reserved
        super().__init__(
            f"requested {requested}p but only {available}p available "
            f"(cap {cap}p, committed {committed}p, reserved {reserved}p)"
        )


class UnknownMandate(LedgerError):
    """No mandate opened under this id. Fail closed rather than assume a cap."""


class UnknownReservation(LedgerError):
    """No reservation under this id, or it was already settled."""


class AlreadySettled(LedgerError):
    """This idempotency key was already charged. Refused, never handed back.

    Handing back the settled reservation is what made a late duplicate cost
    money: the caller took it as a fresh hold, charged the rail, and only then
    failed to commit something already committed. Two orders, one ledger line.
    """


class InFlight(LedgerError):
    """An identical payment holds this key and has not settled yet.

    Raised only when the caller asks for an exclusive hold. Sharing one open
    reservation between two requests lets both reach the rail.
    """


@dataclass(frozen=True)
class Reservation:
    """A hold placed on part of a mandate's budget, not yet charged."""

    id: str
    mandate_id: str
    amount_paise: int
    idempotency_key: str
    created_at: datetime
    settled: bool = False


@dataclass(frozen=True)
class LedgerState:
    """What a mandate has left. Everything in integer paise."""

    mandate_id: str
    cap_paise: int
    committed_paise: int
    reserved_paise: int

    @property
    def available_paise(self) -> int:
        return self.cap_paise - self.committed_paise - self.reserved_paise


class Ledger(Protocol):
    """The interface the gateway depends on.

    MemoryLedger implements it for development and tests; FirestoreLedger will
    implement it against real storage. The gateway never learns which it has,
    so swapping backends changes one line of wiring and no logic.
    """

    def open(self, mandate_id: str, cap_paise: int) -> LedgerState: ...
    def reserve(self, mandate_id: str, amount_paise: int, idempotency_key: str,
                *, exclusive: bool = False) -> Reservation: ...
    def commit(self, reservation_id: str) -> LedgerState: ...
    def release(self, reservation_id: str) -> LedgerState: ...
    def state(self, mandate_id: str) -> LedgerState: ...


@dataclass
class _Mandate:
    cap_paise: int
    committed_paise: int = 0
    reservations: dict[str, Reservation] = field(default_factory=dict)

    @property
    def reserved_paise(self) -> int:
        return sum(r.amount_paise for r in self.reservations.values() if not r.settled)


class MemoryLedger:
    """In-process ledger. Correct, not durable.

    Every mutation happens under one lock. That is heavy-handed and completely
    right for money: a ledger that is fast and occasionally wrong is worse than
    one that is slow and never is.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._mandates: dict[str, _Mandate] = {}
        self._by_reservation: dict[str, str] = {}   # reservation id -> mandate id
        self._by_idem: dict[str, str] = {}          # idempotency key -> reservation id

    def open(self, mandate_id: str, cap_paise: int) -> LedgerState:
        """Register a mandate's ceiling. Safe to call repeatedly.

        Reopening with a different cap is refused. Otherwise a compromised agent
        could simply raise its own limit by asking twice.
        """
        if cap_paise < 0:
            raise ValueError(f"negative cap: {cap_paise}")
        with self._lock:
            existing = self._mandates.get(mandate_id)
            if existing is not None:
                if existing.cap_paise != cap_paise:
                    raise LedgerError(
                        f"mandate {mandate_id[:12]} already open at {existing.cap_paise}p, "
                        f"refusing to reopen at {cap_paise}p"
                    )
            else:
                self._mandates[mandate_id] = _Mandate(cap_paise=cap_paise)
            return self._state(mandate_id)

    def reserve(self, mandate_id: str, amount_paise: int, idempotency_key: str,
                *, exclusive: bool = False) -> Reservation:
        """Hold budget against the cap, or refuse.

        Idempotent on the key. A repeat of the same request returns the original
        reservation rather than a second one - which is what stops an in-TTL
        replay from being charged twice. The check lives here, in the same lock
        that guards the budget, because splitting them reintroduces the race
        this method exists to close.

        Two limits on that. A key that already SETTLED is refused with
        AlreadySettled: returning it let a late duplicate charge the rail again.
        And with `exclusive`, an open hold is refused with InFlight rather than
        shared, because the gateway charges whatever reservation it is given and
        two requests holding the same one both reach the rail.
        """
        if amount_paise <= 0:
            raise ValueError(f"reservation must be positive, got {amount_paise}")
        if not idempotency_key.strip():
            raise ValueError("idempotency key is required")

        with self._lock:
            prior_id = self._by_idem.get(idempotency_key)
            if prior_id is not None:
                mandate = self._mandates[self._by_reservation[prior_id]]
                prior = mandate.reservations[prior_id]
                if prior.settled:
                    raise AlreadySettled(
                        f"key {idempotency_key[:12]} was already charged")
                if exclusive:
                    raise InFlight(
                        f"an identical payment holds key {idempotency_key[:12]}")
                return prior

            mandate = self._mandates.get(mandate_id)
            if mandate is None:
                raise UnknownMandate(f"no mandate opened for {mandate_id[:12]}")

            available = mandate.cap_paise - mandate.committed_paise - mandate.reserved_paise
            if amount_paise > available:
                raise InsufficientBudget(
                    requested=amount_paise,
                    available=available,
                    cap=mandate.cap_paise,
                    committed=mandate.committed_paise,
                    reserved=mandate.reserved_paise,
                )

            reservation = Reservation(
                id=uuid.uuid4().hex,
                mandate_id=mandate_id,
                amount_paise=amount_paise,
                idempotency_key=idempotency_key,
                created_at=datetime.now(timezone.utc),
            )
            mandate.reservations[reservation.id] = reservation
            self._by_reservation[reservation.id] = mandate_id
            self._by_idem[idempotency_key] = reservation.id
            return reservation

    def commit(self, reservation_id: str) -> LedgerState:
        """The payment succeeded. Turn the hold into spend."""
        with self._lock:
            mandate_id, mandate, reservation = self._locate(reservation_id)
            mandate.committed_paise += reservation.amount_paise
            mandate.reservations[reservation_id] = Reservation(
                **{**reservation.__dict__, "settled": True}
            )
            return self._state(mandate_id)

    def release(self, reservation_id: str) -> LedgerState:
        """The payment failed. Give the budget back.

        The idempotency key is released too. A payment that never happened
        should be retryable - only a *successful* charge must stay pinned.
        """
        with self._lock:
            mandate_id, mandate, reservation = self._locate(reservation_id)
            del mandate.reservations[reservation_id]
            del self._by_reservation[reservation_id]
            self._by_idem.pop(reservation.idempotency_key, None)
            return self._state(mandate_id)

    def state(self, mandate_id: str) -> LedgerState:
        with self._lock:
            return self._state(mandate_id)

    # --- internals, all called with the lock already held ------------------

    def _locate(self, reservation_id: str) -> tuple[str, _Mandate, Reservation]:
        mandate_id = self._by_reservation.get(reservation_id)
        if mandate_id is None:
            raise UnknownReservation(f"no open reservation {reservation_id[:12]}")
        mandate = self._mandates[mandate_id]
        reservation = mandate.reservations[reservation_id]
        if reservation.settled:
            raise UnknownReservation(f"reservation {reservation_id[:12]} already settled")
        return mandate_id, mandate, reservation

    def _state(self, mandate_id: str) -> LedgerState:
        mandate = self._mandates.get(mandate_id)
        if mandate is None:
            raise UnknownMandate(f"no mandate opened for {mandate_id[:12]}")
        return LedgerState(
            mandate_id=mandate_id,
            cap_paise=mandate.cap_paise,
            committed_paise=mandate.committed_paise,
            reserved_paise=mandate.reserved_paise,
        )


# --- Firestore ------------------------------------------------------------
#
# Same protocol, durable storage. The gateway never learns which backend it has.
#
# One design note that matters. The obvious schema is "reservations are
# documents, sum them to get the held total" - but Firestore transactions cannot
# freely query inside themselves, and summing a growing collection on every
# payment gets slower forever. So `reserved_paise` is a counter on the mandate
# document, adjusted in the same transaction that writes the reservation.
#
# That makes the mandate document a hot document, which is Firestore's least
# favourite pattern (roughly one sustained write per second each). At demo scale
# it never bites, and it is the honest trade: a relational database with
# SELECT ... FOR UPDATE would express this invariant more naturally. Firestore is
# here because ATA requires a Google Cloud service, not because it is the best
# fit for a ledger.


class FirestoreLedger:
    """Durable ledger. Every mutation runs inside a Firestore transaction.

    Layout:
        mandates/{mandate_id}                     cap, committed, reserved
        mandates/{mandate_id}/reservations/{id}   amount, idem key, settled
        mandates/{mandate_id}/idem/{key}          -> reservation id
    """

    def __init__(self, project: str | None = None, prefix: str = "mandates") -> None:
        from google.cloud import firestore

        self._firestore = firestore
        self._db = firestore.Client(project=project) if project else firestore.Client()
        self._prefix = prefix

    def _mandate_ref(self, mandate_id: str):
        return self._db.collection(self._prefix).document(mandate_id)

    def open(self, mandate_id: str, cap_paise: int) -> LedgerState:
        if cap_paise < 0:
            raise ValueError(f"negative cap: {cap_paise}")
        ref = self._mandate_ref(mandate_id)
        snapshot = ref.get()
        if snapshot.exists:
            existing = snapshot.to_dict()
            if existing["cap_paise"] != cap_paise:
                raise LedgerError(
                    f"mandate {mandate_id[:12]} already open at {existing['cap_paise']}p, "
                    f"refusing to reopen at {cap_paise}p"
                )
        else:
            ref.set({"cap_paise": cap_paise, "committed_paise": 0, "reserved_paise": 0})
        return self.state(mandate_id)

    def reserve(self, mandate_id: str, amount_paise: int, idempotency_key: str,
                *, exclusive: bool = False) -> Reservation:
        if amount_paise <= 0:
            raise ValueError(f"reservation must be positive, got {amount_paise}")
        if not idempotency_key.strip():
            raise ValueError("idempotency key is required")

        mandate_ref = self._mandate_ref(mandate_id)
        idem_ref = mandate_ref.collection("idem").document(idempotency_key)
        reservation_id = uuid.uuid4().hex
        reservation_ref = mandate_ref.collection("reservations").document(reservation_id)

        @self._firestore.transactional
        def txn(transaction):
            # Reads first - Firestore requires every read in a transaction to
            # precede every write.
            prior = idem_ref.get(transaction=transaction)
            if prior.exists:
                held = (
                    mandate_ref.collection("reservations")
                    .document(prior.to_dict()["reservation_id"])
                    .get(transaction=transaction)
                )
                # Same two refusals as MemoryLedger.reserve, for the same reasons.
                if (held.to_dict() or {}).get("settled"):
                    raise AlreadySettled(
                        f"key {idempotency_key[:12]} was already charged")
                if exclusive:
                    raise InFlight(
                        f"an identical payment holds key {idempotency_key[:12]}")
                return held.id, held.to_dict()

            snapshot = mandate_ref.get(transaction=transaction)
            if not snapshot.exists:
                raise UnknownMandate(f"no mandate opened for {mandate_id[:12]}")
            m = snapshot.to_dict()

            available = m["cap_paise"] - m["committed_paise"] - m["reserved_paise"]
            if amount_paise > available:
                raise InsufficientBudget(
                    requested=amount_paise, available=available, cap=m["cap_paise"],
                    committed=m["committed_paise"], reserved=m["reserved_paise"],
                )

            record = {
                "amount_paise": amount_paise,
                "idempotency_key": idempotency_key,
                "created_at": datetime.now(timezone.utc),
                "settled": False,
            }
            transaction.set(reservation_ref, record)
            transaction.set(idem_ref, {"reservation_id": reservation_id})
            # Reverse index: the gateway holds only a reservation id when it
            # settles, and a reservation lives under its mandate. One small
            # write here buys an O(1) lookup instead of a scan.
            transaction.set(
                self._db.collection(f"{self._prefix}_index").document(reservation_id),
                {"mandate_id": mandate_id},
            )
            transaction.update(
                mandate_ref,
                {"reserved_paise": self._firestore.Increment(amount_paise)},
            )
            return reservation_id, record

        found_id, data = txn(self._db.transaction())
        return Reservation(
            id=found_id,
            mandate_id=mandate_id,
            amount_paise=data["amount_paise"],
            idempotency_key=data["idempotency_key"],
            created_at=data["created_at"],
            settled=data.get("settled", False),
        )

    def commit(self, reservation_id: str) -> LedgerState:
        mandate_id, mandate_ref, reservation_ref = self._locate(reservation_id)

        @self._firestore.transactional
        def txn(transaction):
            snapshot = reservation_ref.get(transaction=transaction)
            if not snapshot.exists or snapshot.to_dict().get("settled"):
                raise UnknownReservation(f"no open reservation {reservation_id[:12]}")
            amount = snapshot.to_dict()["amount_paise"]
            transaction.update(reservation_ref, {"settled": True})
            transaction.update(mandate_ref, {
                "committed_paise": self._firestore.Increment(amount),
                "reserved_paise": self._firestore.Increment(-amount),
            })

        txn(self._db.transaction())
        return self.state(mandate_id)

    def release(self, reservation_id: str) -> LedgerState:
        mandate_id, mandate_ref, reservation_ref = self._locate(reservation_id)

        @self._firestore.transactional
        def txn(transaction):
            snapshot = reservation_ref.get(transaction=transaction)
            if not snapshot.exists or snapshot.to_dict().get("settled"):
                raise UnknownReservation(f"no open reservation {reservation_id[:12]}")
            data = snapshot.to_dict()
            transaction.delete(reservation_ref)
            transaction.delete(mandate_ref.collection("idem").document(data["idempotency_key"]))
            transaction.delete(
                self._db.collection(f"{self._prefix}_index").document(reservation_id)
            )
            transaction.update(
                mandate_ref,
                {"reserved_paise": self._firestore.Increment(-data["amount_paise"])},
            )

        txn(self._db.transaction())
        return self.state(mandate_id)

    def state(self, mandate_id: str) -> LedgerState:
        snapshot = self._mandate_ref(mandate_id).get()
        if not snapshot.exists:
            raise UnknownMandate(f"no mandate opened for {mandate_id[:12]}")
        m = snapshot.to_dict()
        return LedgerState(
            mandate_id=mandate_id,
            cap_paise=m["cap_paise"],
            committed_paise=m["committed_paise"],
            reserved_paise=m["reserved_paise"],
        )

    def _locate(self, reservation_id: str):
        """Resolve a reservation id to its mandate via the reverse index."""
        entry = self._db.collection(f"{self._prefix}_index").document(reservation_id).get()
        if not entry.exists:
            raise UnknownReservation(f"no open reservation {reservation_id[:12]}")
        mandate_id = entry.to_dict()["mandate_id"]
        mandate_ref = self._mandate_ref(mandate_id)
        return mandate_id, mandate_ref, mandate_ref.collection("reservations").document(
            reservation_id
        )


def from_env() -> Ledger:
    """FirestoreLedger when a project is configured, MemoryLedger otherwise.

    Development and tests must never require cloud credentials, so absence of
    configuration degrades to in-memory rather than failing.
    """
    project = os.getenv("GOOGLE_CLOUD_PROJECT", "").strip()
    if not project:
        return MemoryLedger()
    try:
        return FirestoreLedger(project=project)
    except Exception:  # noqa: BLE001 - unreachable Firestore must not stop local work
        return MemoryLedger()
