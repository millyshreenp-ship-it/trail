"""Optional device acknowledgements and blinded audit commitments."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.security.canonical_json import canonical_json_bytes


class ExtensionRejected(ValueError):
    pass


class EvidenceExtensions:
    def __init__(self, store, secret: bytes, tokens, clock):
        self.store = store
        self.clock = clock
        self.tokens = tokens
        self.signing_key = Ed25519PrivateKey.from_private_bytes(hmac.new(secret, b"device-challenge-signing-v1", hashlib.sha256).digest())
        with store._lock:
            store._conn.executescript("""
            CREATE TABLE IF NOT EXISTS verification_devices (tenant TEXT NOT NULL, device_id TEXT NOT NULL, public_key TEXT NOT NULL, active INTEGER NOT NULL, PRIMARY KEY(tenant,device_id));
            CREATE TABLE IF NOT EXISTS device_challenges (tenant TEXT NOT NULL, challenge_id TEXT NOT NULL, event_id TEXT NOT NULL, device_id TEXT NOT NULL, payload_json TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,challenge_id));
            CREATE TABLE IF NOT EXISTS audit_checkpoints (tenant TEXT NOT NULL, checkpoint_id TEXT NOT NULL, commitment TEXT NOT NULL, blinding TEXT NOT NULL, max_seq INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant,checkpoint_id));
            """)

    def enroll(self, tenant: str, device_id: str, public_key: str):
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        except Exception:
            raise ExtensionRejected("invalid device public key") from None
        with self.store._lock:
            existing = self.store._conn.execute("SELECT public_key FROM verification_devices WHERE tenant=? AND device_id=?", (tenant, device_id)).fetchone()
            if existing and existing[0] != public_key:
                raise ExtensionRejected("device identity conflict")
            self.store._conn.execute("INSERT OR REPLACE INTO verification_devices VALUES(?,?,?,1)", (tenant, device_id, public_key))
        return {"device_id": device_id, "active": True, "assurance": "prototype_software_key; hardware provisioning not certified"}

    def revoke(self, tenant: str, device_id: str):
        with self.store._lock:
            self.store._conn.execute("UPDATE verification_devices SET active=0 WHERE tenant=? AND device_id=?", (tenant, device_id))
        return {"device_id": device_id, "active": False}

    def _device(self, tenant, device_id):
        row = self.store._conn.execute("SELECT public_key FROM verification_devices WHERE tenant=? AND device_id=? AND active=1", (tenant, device_id)).fetchone()
        if row is None:
            raise ExtensionRejected("device unavailable")
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(row[0], validate=True))

    def challenge(self, tenant: str, event_id: str, device_id: str, event_details: dict | None = None):
        self._device(tenant, device_id)
        decision = self.store.get_decision(tenant, event_id)
        current = self.clock()
        if decision is None or decision["action"] not in {"WARN_AND_VERIFY", "STEP_UP", "ANALYST_REVIEW"} or current >= datetime.fromisoformat(decision["expires_at"]):
            raise ExtensionRejected("decision unavailable or ineligible")
        payload = {"schema_version": "earlytrace.device.challenge.v1", "challenge_id": "challenge_" + secrets.token_hex(16), "device_id": device_id, "event_id": event_id, "audit_id": decision["audit_id"], "action": "ACKNOWLEDGE_REVIEW", "risk_band": decision["risk_band"], "expires_at": min(current + timedelta(minutes=2), datetime.fromisoformat(decision["expires_at"])).astimezone(timezone.utc).isoformat(), "nonce": secrets.token_hex(16), **(event_details or {})}
        message = canonical_json_bytes(payload)
        with self.store._lock:
            self.store._conn.execute("INSERT INTO device_challenges VALUES(?,?,?,?,?,?,0)", (tenant, payload["challenge_id"], event_id, device_id, message.decode(), payload["expires_at"]))
        return {"payload": payload, "message_b64": base64.b64encode(message).decode(), "server_signature_b64": base64.b64encode(self.signing_key.sign(message)).decode(), "server_public_key_b64": base64.b64encode(self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(), "effect": "recorded_only", "pinning_required": True}

    def acknowledge(self, tenant: str, challenge_id: str, signature_b64: str):
        with self.store._lock:
            self.store._transaction()
            try:
                row = self.store._conn.execute("SELECT * FROM device_challenges WHERE tenant=? AND challenge_id=?", (tenant, challenge_id)).fetchone()
                if row is None or row["used"] or self.clock() >= datetime.fromisoformat(row["expires_at"]):
                    raise ExtensionRejected("challenge unavailable")
                public = self._device(tenant, row["device_id"])
                try:
                    public.verify(base64.b64decode(signature_b64, validate=True), row["payload_json"].encode() + b"\nACKNOWLEDGE_REVIEW")
                except Exception:
                    raise ExtensionRejected("invalid acknowledgement") from None
                audit = self.store._audit_locked(tenant, row["event_id"], "DEVICE_ACKNOWLEDGEMENT", {"device_id": row["device_id"], "effect": "recorded_only"})
                self.store._conn.execute("UPDATE device_challenges SET used=1 WHERE tenant=? AND challenge_id=?", (tenant, challenge_id))
                self.store._conn.commit()
                return {"challenge_id": challenge_id, "audit_id": audit["audit_id"], "effect": "recorded_only", "assurance": "device_signature_not_proof_of_uncoerced_intent"}
            except Exception:
                self.store._conn.rollback()
                raise

    def checkpoint(self, tenant: str):
        rows = [row for row in self.store.audit_entries() if row["tenant"] == tenant]
        if not rows:
            raise ExtensionRejected("no audit evidence")
        blinding = secrets.token_hex(32)
        commitment = hashlib.sha256(b"earlytrace-checkpoint-v1" + bytes.fromhex(blinding) + canonical_json_bytes(rows)).hexdigest()
        identifier = "checkpoint_" + secrets.token_hex(16)
        created = self.clock().isoformat()
        with self.store._lock:
            self.store._conn.execute("INSERT INTO audit_checkpoints VALUES(?,?,?,?,?,?)", (tenant, identifier, commitment, blinding, max(row["seq"] for row in rows), created))
        return {"checkpoint_id": identifier, "commitment": commitment, "created_at": created, "entries": len(rows), "network": "solana-devnet", "status": "not_published", "claim": "issuer-authored integrity commitment, not proof of fraud"}

    def verify_checkpoint(self, tenant: str, checkpoint_id: str):
        row = self.store._conn.execute("SELECT * FROM audit_checkpoints WHERE tenant=? AND checkpoint_id=?", (tenant, checkpoint_id)).fetchone()
        if row is None:
            raise ExtensionRejected("checkpoint unavailable")
        records = [record for record in self.store.audit_entries() if record["tenant"] == tenant and record["seq"] <= row["max_seq"]]
        actual = hashlib.sha256(b"earlytrace-checkpoint-v1" + bytes.fromhex(row["blinding"]) + canonical_json_bytes(records)).hexdigest()
        return {"checkpoint_id": checkpoint_id, "intact": hmac.compare_digest(actual, row["commitment"]), "commitment": row["commitment"]}