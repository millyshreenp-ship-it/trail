"""Hash-chained, append-only audit log with optional durable JSONL sink."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | None = None):
        self._entries: list[dict] = []
        self._lock = threading.Lock()
        self._path = path
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self._entries = [json.loads(line) for line in fh if line.strip()]
            ok, bad = self.verify_chain()
            if not ok:
                raise RuntimeError(f"Audit log {path} failed integrity check at seq {bad}; refusing to start")

    def append(self, actor: str, role: str, action: str, subject: str,
               reason_code: str | None = None, details: dict | None = None) -> dict:
        with self._lock:
            prev = self._entries[-1]["hash"] if self._entries else GENESIS
            body = {
                "audit_id": "AUD-" + uuid.uuid4().hex[:10].upper(),
                "seq": len(self._entries) + 1,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "role": role,
                "action": action,
                "subject": subject,
                "reason_code": reason_code,
                "details": details or {},
                "prev_hash": prev,
            }
            body["hash"] = self._hash(body)
            if self._path:  # write-ahead: persist before acknowledging
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(body, default=str) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            self._entries.append(body)
            return dict(body)

    @staticmethod
    def _hash(body: dict) -> str:
        payload = {k: v for k, v in body.items() if k != "hash"}
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()

    def verify_chain(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_seq)."""
        prev = GENESIS
        for e in self._entries:
            if e["prev_hash"] != prev or self._hash(e) != e["hash"]:
                return False, e["seq"]
            prev = e["hash"]
        return True, None

    def entries(self, subject: str | None = None) -> list[dict]:
        with self._lock:
            return [dict(e) for e in self._entries if subject is None or e["subject"] == subject]

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            return next((dict(e) for e in self._entries if e["audit_id"] == audit_id), None)
