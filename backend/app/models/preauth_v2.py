"""Wire-only v2 request contracts; server-owned event fields are absent."""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from app.models.preauth import (
    ConsentScope, EventAttestation, EventSource, PayeeAgeBucket, SessionContext,
)


class PreAuthWireEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["earlytrace.preauth.v2"]
    event_id: str = Field(pattern=r"^evt_[a-z0-9_-]{6,64}$")
    occurred_at: datetime
    institution_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,32}$")
    event_source: EventSource
    rail: Literal["UPI", "IMPS", "NEFT", "RTGS", "WALLET"]
    source_token: str = Field(pattern=r"^tok_[0-9a-f]{32}$")
    payee_token: str = Field(pattern=r"^tok_[0-9a-f]{32}$")
    amount_bucket: Literal["0_1k", "1k_10k", "10k_50k", "50k_100k", "100k_500k", "500k_plus"]
    payee_age_bucket: PayeeAgeBucket
    session_context: SessionContext
    consent_scope: ConsentScope
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^idem_[A-Za-z0-9_-]{8,64}$")


class PreAuthWireSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["earlytrace.preauth.v2"]
    event: PreAuthWireEvent
    attestation: EventAttestation
    trace_id: str = Field(pattern=r"^trace_[a-z0-9_-]{4,64}$")
    idempotency_key: str = Field(pattern=r"^idem_[A-Za-z0-9_-]{8,64}$")
    declared_payee_age_bucket: PayeeAgeBucket | None = None
    declared_session_context: SessionContext | None = None
    declared_consent_scope: ConsentScope | None = None
    fixture_id: str | None = Field(default=None, pattern=r"^fx_[a-z0-9_-]{8,64}$")

    def metadata_matches(self) -> bool:
        return self.trace_id == self.event.trace_id and self.idempotency_key == self.event.idempotency_key
