"""Trail Hub API. Run locally with ``uvicorn app.main:app --app-dir backend``."""
from __future__ import annotations

import logging
import os
import re
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api import beacons, cases, complaints, graph, institutions, preauth, review, workspace, extensions
from app.config import (
    PROFILE_SANDBOX,
    VERSION,
    get_settings,
)
from app.assistance import configured_provider
from app.security.audit import verify_ledgers
from app.security.rbac import default_dev_users
from app.state import get_state

cfg = get_settings()
cfg.validate()
logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("trail.http")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MAX_BODY = 65_536


class _BodyTooLarge(Exception):
    """Internal signal raised before a chunked preauth body is accumulated."""

app = FastAPI(
    title="Trail Hub API",
    version=VERSION,
    description="Cross-institution scam-trail intelligence. Every action is proposed by the system and approved by a human.",
    docs_url="/docs" if cfg.docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if cfg.docs_enabled else None,
)
app.add_middleware(
    CORSMiddleware,
    # CORS is explicit. There is no wildcard, null-origin, or implicit local
    # origin; the sandbox defaults are the only local development exception.
    allow_origins=list(cfg.cors_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Institution-Id", "X-Request-Id"],
    allow_credentials=False,
)


def _request_id(request: Request) -> str:
    candidate = request.headers.get("X-Request-Id", "")
    return candidate if _REQUEST_ID.fullmatch(candidate) else uuid.uuid4().hex[:16]


def _safe_headers(rid: str) -> dict[str, str]:
    return {
        "X-Request-Id": rid,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'none'",
        "Cache-Control": "no-store",
    }


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = _request_id(request)
    if request.method in {"POST", "PUT", "PATCH"}:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                return JSONResponse(status_code=400, content={"detail": "invalid content length"}, headers=_safe_headers(rid))
            if declared < 0:
                return JSONResponse(status_code=400, content={"detail": "invalid content length"}, headers=_safe_headers(rid))
            if request.url.path.startswith("/preauth") and declared > _MAX_BODY:
                return JSONResponse(status_code=413, content={"detail": "request body too large"}, headers=_safe_headers(rid))
        # Reading the bounded preauth body here also covers chunked requests;
        # the receive wrapper stops accumulation at the first oversized chunk.
        if request.url.path.startswith("/preauth"):
            received = 0
            original_receive = request._receive

            async def limited_receive():
                nonlocal received
                message = await original_receive()
                if message.get("type") == "http.request":
                    received += len(message.get("body", b""))
                    if received > _MAX_BODY:
                        raise _BodyTooLarge
                return message

            request._receive = limited_receive
            try:
                await request.body()
            except _BodyTooLarge:
                return JSONResponse(status_code=413, content={"detail": "request body too large"}, headers=_safe_headers(rid))
    started = time.perf_counter()
    response = await call_next(request)
    response.headers.update(_safe_headers(rid))
    if request.url.path.startswith("/workspace"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    route = getattr(request.scope.get("route"), "path", request.url.path)
    log.info(
        "http_request route=%s method=%s status=%s latency_ms=%.1f request_id=%s",
        route,
        request.method,
        response.status_code,
        (time.perf_counter() - started) * 1000,
        rid,
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, __: RequestValidationError):
    # Never return Pydantic input/context fragments, which may contain a raw
    # value from a rejected body.
    return JSONResponse(status_code=422, content={"detail": "invalid request"})


for route in (institutions.router, complaints.router, beacons.router, cases.router, review.router, graph.router, preauth.router, workspace.router, extensions.router):
    app.include_router(route)


def _safe_status(state=None) -> dict[str, object]:
    storage_mode = cfg.storage_mode
    if state is not None:
        storage_mode = getattr(state.preauth_store, "path", cfg.preauth_path) == ":memory:" and "memory" or "sqlite_wal"
    return {
        "version": VERSION,
        "profile": cfg.profile,
        "live_integrations": False,
        "data_status": "synthetic",
        "storage_mode": storage_mode,
        "engine_version": "earlytrace-b0b1-heuristic-v2",
        "feature_contracts": {"b0": "b0.v2", "b1": "motif.v2"},
        "calibration_status": "NOT_FITTED",
        "calibration_id": None,
        "demo_keys_enabled": cfg.demo_keys_enabled,
        "network_runtime_enabled": configured_provider() != "deterministic",
        "assistant_provider": configured_provider(),
        "production_supported": False,
    }


@app.get("/healthz", tags=["ops"])
def healthz():
    """Liveness only: this endpoint does not inspect storage or audit state."""
    return {"status": "ok", "version": VERSION}


@app.get("/readyz", tags=["ops"])
def readyz():
    """Readiness for the selected local/staging profile."""
    state = get_state()
    try:
        health = verify_ledgers(state.audit, state.preauth_store)
        ledger_ok = bool(health["ready"])
    except Exception:
        health = {"legacy": {"intact": False, "first_bad_seq": None}, "preauth": {"intact": False, "first_bad_seq": None}}
        ledger_ok = False
    config_errors = cfg.validation_errors()
    lock_ok = cfg.profile == PROFILE_SANDBOX or cfg.dependency_lock_verified()
    checks = {
        "configuration": not config_errors,
        "legacy_audit": bool(health["legacy"]["intact"]),
        "paud_store": bool(health["preauth"]["intact"]),
        "dependency_lock": lock_ok,
        "live_integrations_disabled": cfg.live_integrations is False,
        "synthetic_provenance": cfg.data_status == "synthetic",
    }
    ready = ledger_ok and all(checks.values())
    return {
        **_safe_status(state),
        "ready": ready,
        "checks": checks,
        "configuration_errors": list(config_errors),
        "audit_chain_intact": bool(health["legacy"]["intact"]),
        "preauth_chain_intact": bool(health["preauth"]["intact"]),
        "first_bad_seq": health["legacy"]["first_bad_seq"],
        "first_bad_paud_seq": health["preauth"]["first_bad_seq"],
    }


@app.get("/version", tags=["ops"])
def version():
    """Safe build/runtime status; no secrets, API keys, or credential material."""
    return _safe_status()


@app.get("/meta", tags=["ops"])
def meta():
    """Public console bootstrap. Sandbox accounts are exposed only in sandbox."""
    out = {"name": "Trail", **_safe_status()}
    state = get_state()
    if cfg.profile in {"sandbox", "staging"} and state._earlytrace_submission:
        out["earlytrace_fixture_submission"] = state._earlytrace_submission
    if cfg.profile == PROFILE_SANDBOX:
        public_demo = os.environ.get("TRAIL_PUBLIC_DEMO") == "1"
        out["public_demo"] = public_demo
        out["sandbox_accounts"] = [
            {"label": f"{principal.user_id} · {principal.role.value}", "key": key}
            for key, principal in default_dev_users().items()
            if principal.role.value != "institution_admin" and (not public_demo or key == "dev-preauth-a-key")
        ]
    return out


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/workspace/" if (Path(__file__).resolve().parents[2] / "frontend" / "dist").exists() else "/console/")


_frontend = Path(__file__).resolve().parents[2] / "frontend"
if _frontend.exists():
    app.mount("/console", StaticFiles(directory=_frontend, html=True), name="console")
if (_frontend / "dist").exists():
    app.mount("/workspace", StaticFiles(directory=_frontend / "dist", html=True), name="workspace")
