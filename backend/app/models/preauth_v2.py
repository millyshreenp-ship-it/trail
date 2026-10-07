"""Wire-only v2 request contracts; server-owned event fields are absent."""
from __future__ import annotations

from app.models.preauth import PreAuthSubmission, PreAuthSubmissionEvent

# Keep the historical explicit wire names as aliases to the sole public model
# definitions.  This prevents the API and contract module from drifting apart.
PreAuthWireEvent = PreAuthSubmissionEvent


class PreAuthWireSubmission(PreAuthSubmission):
    def metadata_matches(self) -> bool:
        return self.trace_id == self.event.trace_id and self.idempotency_key == self.event.idempotency_key
