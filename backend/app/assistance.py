"""Optional read-only model assistance with a validated deterministic fallback."""
from __future__ import annotations

import json
import os
import re

import httpx
from pydantic import BaseModel, ConfigDict, Field


class ReviewDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=1600)
    reason_codes: list[str] = Field(max_length=32)


def configured_provider() -> str:
    value = os.environ.get("TRAIL_ASSISTANT_PROVIDER", "deterministic")
    return value if os.environ.get("TRAIL_ASSISTANT_ENABLED") == "1" and value in {"vertex", "bedrock"} else "deterministic"


def _prompt(decision: dict) -> str:
    evidence = {key: decision[key] for key in ("action", "evidence_coverage", "participation", "consent_outcome", "score_kind", "calibration_status")}
    evidence["reason_codes"] = [reason["code"] for reason in decision["reasons"]]
    return "Return JSON with only summary and reason_codes. Draft a short cautious analyst summary using only the supplied evidence. Do not invent facts, change the recommendation, accuse anyone, claim fraud is proven, or request payment blocking. Scores are uncalibrated. reason_codes must be copied from evidence. Evidence: " + json.dumps(evidence, sort_keys=True)


def _vertex(prompt: str) -> str:
    import google.auth
    from google.auth.transport.requests import Request

    project = os.environ["TRAIL_ASSISTANT_PROJECT"]
    region = os.environ["TRAIL_ASSISTANT_REGION"]
    model = os.environ["TRAIL_ASSISTANT_MODEL"]
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,62}", project) or not re.fullmatch(r"[a-z]+[0-9]?-[a-z]+[0-9]", region) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", model):
        raise ValueError("invalid assistant configuration")
    identity, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    identity.refresh(Request())
    endpoint = f"https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/google/models/{model}:generateContent"
    response = httpx.post(endpoint, headers={"Authorization": f"Bearer {identity.token}"}, json={"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0, "maxOutputTokens": 500, "responseMimeType": "application/json"}}, timeout=8)
    response.raise_for_status()
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]


def _bedrock(prompt: str) -> str:
    import boto3
    from botocore.config import Config

    client = boto3.client("bedrock-runtime", region_name=os.environ["TRAIL_ASSISTANT_REGION"], config=Config(connect_timeout=3, read_timeout=8, retries={"max_attempts": 0}))
    response = client.converse(modelId=os.environ["TRAIL_ASSISTANT_MODEL"], messages=[{"role": "user", "content": [{"text": prompt}]}], inferenceConfig={"maxTokens": 500, "temperature": 0})
    return response["output"]["message"]["content"][0]["text"]


def summarize(decision: dict) -> dict:
    baseline = {"provider": "deterministic", "ai_generated": False, "action": decision["action"], "summary": f"Advisory {decision['action'].lower().replace('_', ' ')}. Evidence coverage is {decision['evidence_coverage']:.0%}; participation is {decision['participation']}. The score is not a probability. Verify independently before any institution-controlled action.", "reason_codes": [reason["code"] for reason in decision["reasons"]], "authority": "read_only", "audit_id": decision["audit_id"], "status": "deterministic"}
    provider = configured_provider()
    if provider == "deterministic":
        return baseline
    try:
        raw = (_vertex if provider == "vertex" else _bedrock)(_prompt(decision))
        draft = ReviewDraft.model_validate_json(raw)
        if not set(draft.reason_codes) <= set(baseline["reason_codes"]):
            raise ValueError("unsupported evidence reference")
        return {**baseline, **draft.model_dump(), "provider": provider, "ai_generated": True, "status": "draft_requires_human_review"}
    except Exception:
        return {**baseline, "status": "provider_unavailable_or_output_rejected", "requested_provider": provider}