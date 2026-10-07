"""Durable SQLite storage for the EarlyTrace pre-authorisation ledger.

PAUD is the authoritative EarlyTrace ledger.  The legacy JSONL audit log is
not part of an EarlyTrace acknowledgement transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

GENESIS = "0" * 64


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _hash_row(row: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class ReservationLost(RuntimeError):
    pass


class StoreConflict(RuntimeError):
    pass


class DecisionInProgress(RuntimeError):
    pass


@dataclass(frozen=True)
class Reservation:
    tenant: str
    event_id: str
    idempotency_key: str
    body_hash: str
    reservation_id: str
    lease_token: str
    generation: int


@dataclass(frozen=True)
class ReserveResult:
    reservation: Reservation | None = None
    decision: dict[str, Any] | None = None
    audit_id: str | None = None
    duplicate: bool = False


class DecisionStore(Protocol):
    def reserve(self, tenant: str, event_id: str, idempotency_key: str, body_hash: str, now: datetime | None = None) -> ReserveResult: ...
    def commit_decision(self, reservation: Reservation, decision: dict[str, Any], details: dict[str, Any] | None = None) -> dict[str, Any]: ...
    def get_decision(self, tenant: str, event_id: str) -> dict[str, Any] | None: ...


class SQLiteDecisionStore:
    """SQLite PAUD store with tenant-qualified idempotency and fencing."""

    def __init__(self, path: str = ":memory:", *, clock=None, lease_seconds: int = 30, tombstone_retention: timedelta = timedelta(days=30)):
        self.path = path
        self.clock = clock or _now
        self.lease_seconds = lease_seconds
        self.tombstone_retention = tombstone_retention
        self._lock = threading.RLock()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._schema()
        # Recover a worker that died before committing.  Recovery is itself
        # transactional and retains the original body hash as a tombstone.
        self.reclaim_expired(self.clock())

    def _configure(self) -> None:
        self._conn.execute("PRAGMA busy_timeout=5000")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")

    def _schema(self) -> None:
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS decisions (
            tenant TEXT NOT NULL, event_id TEXT NOT NULL, body_hash TEXT NOT NULL,
            decision_json TEXT NOT NULL, expires_at TEXT, created_at TEXT NOT NULL,
            PRIMARY KEY (tenant, event_id)
        );
        CREATE TABLE IF NOT EXISTS idempotency (
            tenant TEXT NOT NULL, idempotency_key TEXT NOT NULL, event_id TEXT NOT NULL,
            body_hash TEXT NOT NULL, status TEXT NOT NULL, tombstone_until TEXT,
            PRIMARY KEY (tenant, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS reservations (
            tenant TEXT NOT NULL, event_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
            body_hash TEXT NOT NULL, reservation_id TEXT NOT NULL, lease_token TEXT NOT NULL,
            generation INTEGER NOT NULL, status TEXT NOT NULL, lease_until TEXT NOT NULL,
            PRIMARY KEY (tenant, event_id), UNIQUE (tenant, reservation_id)
        );
        CREATE TABLE IF NOT EXISTS tombstones (
            tenant TEXT NOT NULL, idempotency_key TEXT NOT NULL, body_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL, PRIMARY KEY (tenant, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS action_receipts (
            tenant TEXT NOT NULL, event_id TEXT NOT NULL, action_kind TEXT NOT NULL,
            action_id TEXT NOT NULL, body_hash TEXT NOT NULL, receipt_json TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (tenant, event_id, action_kind, action_id)
        );
        CREATE TABLE IF NOT EXISTS feedback_receipts (
            tenant TEXT NOT NULL, event_id TEXT NOT NULL, feedback_id TEXT NOT NULL,
            body_hash TEXT NOT NULL, receipt_json TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY (tenant, event_id, feedback_id)
        );
        CREATE TABLE IF NOT EXISTS paud_audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL UNIQUE,
            ts TEXT NOT NULL, tenant TEXT NOT NULL, event_id TEXT NOT NULL,
            action TEXT NOT NULL, reason_code TEXT, details_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL, hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_decisions_expiry ON decisions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_tombstones_expiry ON tombstones(expires_at);
        """)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(action_receipts)")}
        if "action_kind" not in columns:
            # Upgrade the pre-v2 local table without losing record-only receipts.
            self._conn.execute("ALTER TABLE action_receipts RENAME TO action_receipts_legacy")
            self._conn.execute("""
                CREATE TABLE action_receipts (
                    tenant TEXT NOT NULL, event_id TEXT NOT NULL, action_kind TEXT NOT NULL,
                    action_id TEXT NOT NULL, body_hash TEXT NOT NULL, receipt_json TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, event_id, action_kind, action_id)
                )
            """)
            rows = self._conn.execute("SELECT tenant,event_id,action_id,body_hash,receipt_json,expires_at FROM action_receipts_legacy").fetchall()
            for row in rows:
                receipt = json.loads(row[4])
                self._conn.execute(
                    "INSERT OR IGNORE INTO action_receipts VALUES(?,?,?,?,?,?,?)",
                    (row[0], row[1], str(receipt.get("action", "DISPLAY")), row[2], row[3], row[4], row[5]),
                )
            self._conn.execute("DROP TABLE action_receipts_legacy")

    def _transaction(self):
        self._conn.execute("BEGIN IMMEDIATE")

    def _audit_locked(self, tenant: str, event_id: str, action: str, details: dict[str, Any] | None = None, reason_code: str | None = None) -> dict[str, Any]:
        prior = self._conn.execute("SELECT hash FROM paud_audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = prior[0] if prior else GENESIS
        audit_id = "PAUD-" + uuid.uuid4().hex[:12].upper()
        body = {
            "audit_id": audit_id, "ts": _iso(self.clock()), "tenant": tenant,
            "event_id": event_id, "action": action, "reason_code": reason_code,
            "details": details or {}, "prev_hash": prev,
        }
        body["hash"] = _hash_row(body)
        self._conn.execute(
            "INSERT INTO paud_audit(audit_id,ts,tenant,event_id,action,reason_code,details_json,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (audit_id, body["ts"], tenant, event_id, action, reason_code, json.dumps(body["details"], sort_keys=True), prev, body["hash"]),
        )
        body["source_ledger"] = "preauth"
        return body

    def _reclaim_expired_locked(self, now: datetime) -> int:
        """Reclaim expired leases and orphaned pending idempotency rows."""
        now_s = _iso(now)
        tombstone_until = _iso(now + self.tombstone_retention)
        rows = self._conn.execute(
            "SELECT tenant,event_id,idempotency_key,body_hash,reservation_id,generation "
            "FROM reservations WHERE status='PENDING' AND lease_until<=?",
            (now_s,),
        ).fetchall()
        for row in rows:
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones VALUES(?,?,?,?)",
                (row[0], row[2], row[3], tombstone_until),
            )
            self._audit_locked(row[0], row[1], "PREAUTH_RESERVATION_RECLAIMED", {"generation": int(row[5])})
            self._conn.execute(
                "DELETE FROM reservations WHERE tenant=? AND event_id=? AND reservation_id=?",
                (row[0], row[1], row[4]),
            )
            self._conn.execute(
                "DELETE FROM idempotency WHERE tenant=? AND idempotency_key=? AND status='PENDING'",
                (row[0], row[2]),
            )
        orphaned = self._conn.execute(
            "SELECT i.tenant,i.event_id,i.idempotency_key,i.body_hash "
            "FROM idempotency i LEFT JOIN reservations r "
            "ON r.tenant=i.tenant AND r.idempotency_key=i.idempotency_key "
            "WHERE i.status='PENDING' AND r.idempotency_key IS NULL"
        ).fetchall()
        for row in orphaned:
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones VALUES(?,?,?,?)",
                (row[0], row[2], row[3], tombstone_until),
            )
            self._audit_locked(row[0], row[1], "PREAUTH_RESERVATION_RECLAIMED", {"orphaned": True})
            self._conn.execute(
                "DELETE FROM idempotency WHERE tenant=? AND idempotency_key=? AND status='PENDING'",
                (row[0], row[2]),
            )
        return len(rows) + len(orphaned)

    def reserve(self, tenant: str, event_id: str, idempotency_key: str, body_hash: str, now: datetime | None = None) -> ReserveResult:
        now = now or self.clock()
        now_s = _iso(now)
        with self._lock:
            self._transaction()
            try:
                self._reclaim_expired_locked(now)
                existing = self._conn.execute("SELECT decision_json, body_hash FROM decisions WHERE tenant=? AND event_id=?", (tenant, event_id)).fetchone()
                if existing:
                    if existing[1] != body_hash:
                        raise StoreConflict("event body conflict")
                    return self._finish(self._existing_result(tenant, event_id, existing[0]), commit=True)
                idem = self._conn.execute("SELECT event_id,body_hash,status FROM idempotency WHERE tenant=? AND idempotency_key=?", (tenant, idempotency_key)).fetchone()
                if idem:
                    if idem[1] != body_hash:
                        raise StoreConflict("idempotency body conflict")
                    if idem[2] == "COMMITTED":
                        row = self._conn.execute("SELECT decision_json FROM decisions WHERE tenant=? AND event_id=?", (tenant, idem[0])).fetchone()
                        if row:
                            return self._finish(self._existing_result(tenant, idem[0], row[0]), commit=True)
                    raise DecisionInProgress("decision is in progress")
                tomb = self._conn.execute("SELECT body_hash,expires_at FROM tombstones WHERE tenant=? AND idempotency_key=?", (tenant, idempotency_key)).fetchone()
                if tomb and tomb[1] > now_s:
                    if tomb[0] != body_hash:
                        raise StoreConflict("idempotency tombstone conflict")
                    # Same-body retry is safe after recovery; a different body
                    # remains fenced for the retention window.
                    self._conn.execute("DELETE FROM tombstones WHERE tenant=? AND idempotency_key=?", (tenant, idempotency_key))
                elif tomb:
                    self._conn.execute("DELETE FROM tombstones WHERE tenant=? AND idempotency_key=?", (tenant, idempotency_key))
                old = self._conn.execute("SELECT generation,status,lease_until FROM reservations WHERE tenant=? AND event_id=?", (tenant, event_id)).fetchone()
                if old and old[1] == "PENDING":
                    raise DecisionInProgress("decision is in progress")
                generation = (int(old[0]) + 1) if old else 1
                reservation = Reservation(tenant, event_id, idempotency_key, body_hash, uuid.uuid4().hex, secrets.token_urlsafe(24), generation)
                lease_until = _iso(now + timedelta(seconds=self.lease_seconds))
                self._conn.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?,?)", (tenant, event_id, idempotency_key, body_hash, reservation.reservation_id, reservation.lease_token, generation, "PENDING", lease_until))
                self._conn.execute("INSERT INTO idempotency VALUES(?,?,?,?,?,?)", (tenant, idempotency_key, event_id, body_hash, "PENDING", None))
                self._audit_locked(tenant, event_id, "PREAUTH_RECEIVED", {"status": "reserved"})
                self._conn.commit()
                return ReserveResult(reservation=reservation)
            except Exception:
                self._conn.rollback()
                raise

    def _finish(self, result: ReserveResult, *, commit: bool) -> ReserveResult:
        if commit:
            self._conn.commit()
        return result

    def _existing_result(self, tenant: str, event_id: str, raw: str) -> ReserveResult:
        decision = json.loads(raw)
        audit_id = decision.get("audit_id")
        return ReserveResult(decision=decision, audit_id=audit_id, duplicate=True)

    def commit_decision(self, reservation: Reservation, decision: dict[str, Any], details: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            self._transaction()
            try:
                row = self._conn.execute("SELECT lease_token,generation,status,lease_until FROM reservations WHERE tenant=? AND event_id=? AND reservation_id=?", (reservation.tenant, reservation.event_id, reservation.reservation_id)).fetchone()
                if (
                    not row or row[0] != reservation.lease_token or int(row[1]) != reservation.generation
                    or row[2] != "PENDING" or row[3] <= _iso(self.clock())
                ):
                    raise ReservationLost("reservation lease was fenced")
                audit = self._audit_locked(reservation.tenant, reservation.event_id, "PREAUTH_SCORED", details or {})
                stored = dict(decision)
                stored["audit_id"] = audit["audit_id"]
                self._conn.execute("INSERT INTO decisions VALUES(?,?,?,?,?,?)", (reservation.tenant, reservation.event_id, reservation.body_hash, json.dumps(stored, sort_keys=True), stored.get("expires_at"), _iso(self.clock())))
                self._conn.execute("UPDATE idempotency SET status='COMMITTED' WHERE tenant=? AND idempotency_key=? AND body_hash=?", (reservation.tenant, reservation.idempotency_key, reservation.body_hash))
                self._conn.execute("UPDATE reservations SET status='COMMITTED' WHERE tenant=? AND event_id=? AND reservation_id=?", (reservation.tenant, reservation.event_id, reservation.reservation_id))
                self._conn.commit()
                return stored
            except Exception:
                self._conn.rollback()
                raise

    def fail(self, reservation: Reservation, reason_code: str) -> None:
        with self._lock:
            self._transaction()
            try:
                row = self._conn.execute("SELECT lease_token,generation,status,lease_until FROM reservations WHERE tenant=? AND event_id=? AND reservation_id=?", (reservation.tenant, reservation.event_id, reservation.reservation_id)).fetchone()
                if (
                    not row or row[0] != reservation.lease_token or int(row[1]) != reservation.generation
                    or row[2] != "PENDING" or row[3] <= _iso(self.clock())
                ):
                    raise ReservationLost("reservation lease was fenced")
                self._audit_locked(reservation.tenant, reservation.event_id, "PREAUTH_FAILED", {"status": "failed"}, reason_code)
                self._conn.execute("DELETE FROM idempotency WHERE tenant=? AND idempotency_key=?", (reservation.tenant, reservation.idempotency_key))
                self._conn.execute("DELETE FROM reservations WHERE tenant=? AND event_id=? AND reservation_id=?", (reservation.tenant, reservation.event_id, reservation.reservation_id))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def reclaim_expired(self, now: datetime | None = None) -> int:
        now = now or self.clock()
        with self._lock:
            self._transaction()
            try:
                count = self._reclaim_expired_locked(now)
                self._conn.commit()
                return count
            except Exception:
                self._conn.rollback()
                raise

    def get_decision(self, tenant: str, event_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT decision_json FROM decisions WHERE tenant=? AND event_id=?", (tenant, event_id)).fetchone()
        return json.loads(row[0]) if row else None

    def list_decisions(self, tenant: str, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("invalid decision page")
        with self._lock:
            rows = self._conn.execute("SELECT decision_json FROM decisions WHERE tenant=? ORDER BY created_at DESC,event_id LIMIT ? OFFSET ?", (tenant, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_action(self, tenant: str, event_id: str, action_kind: str, action_id: str) -> tuple[str, dict[str, Any]] | None:
        row = self._conn.execute(
            "SELECT body_hash,receipt_json FROM action_receipts WHERE tenant=? AND event_id=? AND action_kind=? AND action_id=?",
            (tenant, event_id, action_kind, action_id),
        ).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def put_action(self, tenant: str, event_id: str, action_kind: str, action_id: str, body_hash: str, receipt: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._transaction()
            try:
                existing = self.get_action(tenant, event_id, action_kind, action_id)
                if existing:
                    if existing[0] != body_hash:
                        raise StoreConflict("action body conflict")
                    result = dict(existing[1]); result["duplicate"] = True
                    self._conn.commit(); return result
                audit = self._audit_locked(tenant, event_id, "PREAUTH_ACTION_RECORDED", {"action": action_kind, "effect": "recorded_only"})
                receipt = dict(receipt)
                receipt["audit_id"] = audit["audit_id"]
                self._conn.execute(
                    "INSERT INTO action_receipts VALUES(?,?,?,?,?,?,?)",
                    (tenant, event_id, action_kind, action_id, body_hash, json.dumps(receipt, sort_keys=True), receipt["expires_at"]),
                )
                self._conn.commit()
                return receipt
            except Exception:
                self._conn.rollback(); raise

    def get_feedback(self, tenant: str, event_id: str, feedback_id: str) -> tuple[str, dict[str, Any]] | None:
        row = self._conn.execute("SELECT body_hash,receipt_json FROM feedback_receipts WHERE tenant=? AND event_id=? AND feedback_id=?", (tenant, event_id, feedback_id)).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def put_feedback(self, tenant: str, event_id: str, feedback_id: str, body_hash: str, receipt: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._transaction()
            try:
                existing = self.get_feedback(tenant, event_id, feedback_id)
                if existing:
                    if existing[0] != body_hash:
                        raise StoreConflict("feedback body conflict")
                    result = dict(existing[1]); result["duplicate"] = True
                    self._conn.commit(); return result
                audit = self._audit_locked(tenant, event_id, "PREAUTH_FEEDBACK_QUARANTINED", {"feedback_id": feedback_id, "applied_to_model": False}, "QUARANTINE")
                receipt = dict(receipt)
                receipt["audit_id"] = audit["audit_id"]
                self._conn.execute("INSERT INTO feedback_receipts VALUES(?,?,?,?,?,?)", (tenant, event_id, feedback_id, body_hash, json.dumps(receipt, sort_keys=True), _iso(self.clock())))
                self._conn.commit()
                return receipt
            except Exception:
                self._conn.rollback(); raise

    def audit_entries(self, event_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM paud_audit"
        args: tuple[Any, ...] = ()
        if event_id:
            query += " WHERE event_id=?"; args = (event_id,)
        query += " ORDER BY seq"
        rows = self._conn.execute(query, args).fetchall()
        out = []
        for row in rows:
            out.append({"seq": row["seq"], "audit_id": row["audit_id"], "ts": row["ts"], "tenant": row["tenant"], "event_id": row["event_id"], "action": row["action"], "reason_code": row["reason_code"], "details": json.loads(row["details_json"]), "prev_hash": row["prev_hash"], "hash": row["hash"], "source_ledger": "preauth"})
        return out

    def verify_chain(self) -> tuple[bool, int | None]:
        prev = GENESIS
        for row in self._conn.execute("SELECT * FROM paud_audit ORDER BY seq"):
            body = {"audit_id": row["audit_id"], "ts": row["ts"], "tenant": row["tenant"], "event_id": row["event_id"], "action": row["action"], "reason_code": row["reason_code"], "details": json.loads(row["details_json"]), "prev_hash": row["prev_hash"]}
            if row["prev_hash"] != prev or _hash_row(body) != row["hash"]:
                return False, row["seq"]
            prev = row["hash"]
        return True, None

    def purge(self, now: datetime | None = None, *, decision_retention=timedelta(hours=24), tombstone_retention=timedelta(days=30), feedback_retention=timedelta(days=90)) -> dict[str, int]:
        now = now or self.clock(); now_s = _iso(now)
        with self._lock:
            self._transaction()
            try:
                expired = self._conn.execute("SELECT i.tenant,i.idempotency_key,i.body_hash,d.expires_at FROM idempotency i JOIN decisions d ON d.tenant=i.tenant AND d.event_id=i.event_id WHERE d.expires_at IS NOT NULL AND d.expires_at<=?", (now_s,)).fetchall()
                for row in expired:
                    self._conn.execute("INSERT OR REPLACE INTO tombstones VALUES(?,?,?,?)", (row[0], row[1], row[2], _iso(now + tombstone_retention)))
                    self._conn.execute("DELETE FROM idempotency WHERE tenant=? AND idempotency_key=?", (row[0], row[1]))
                cur = self._conn.execute("DELETE FROM decisions WHERE expires_at IS NOT NULL AND expires_at<=?", (now_s,))
                self._conn.execute("DELETE FROM action_receipts WHERE expires_at<=?", (now_s,))
                old_tombstones = self._conn.execute("DELETE FROM tombstones WHERE expires_at<=?", (now_s,)).rowcount
                old_feedback = self._conn.execute("DELETE FROM feedback_receipts WHERE created_at<=?", (_iso(now - feedback_retention),)).rowcount
                self._conn.commit()
                return {"decisions": cur.rowcount, "tombstones": len(expired) + old_tombstones, "feedback": old_feedback}
            except Exception:
                self._conn.rollback(); raise

    def checkpoint(self) -> tuple:
        """Checkpoint WAL without rewriting the PAUD chain."""
        if self.path == ":memory:":
            return (0, 0, 0)
        return tuple(self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())

    def close(self) -> None:
        self._conn.close()


class MemoryDecisionStore(SQLiteDecisionStore):
    """Demo/test adapter; uses an isolated in-memory SQLite PAUD ledger."""
    def __init__(self, *, clock=None):
        super().__init__(":memory:", clock=clock)
