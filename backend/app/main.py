"""Trail Hub API.  Run: uvicorn app.main:app --app-dir backend"""
import logging
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import beacons, cases, complaints, graph, institutions, preauth, review
from app.config import VERSION, get_settings
from app.security.audit import verify_ledgers
from app.security.rbac import default_dev_users
from app.state import get_state

cfg = get_settings()
cfg.validate()
logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("trail.http")

app = FastAPI(title="Trail Hub API", version=VERSION,
              description="Cross-institution scam-trail intelligence. Every action is proposed by the system and approved by a human.",
              docs_url=None if cfg.is_production else "/docs", redoc_url=None, openapi_url=None if cfg.is_production else "/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=list(cfg.cors_origins) + ([] if cfg.is_production else ["null", "http://127.0.0.1:8000"]), allow_methods=["GET", "POST"],
                   allow_headers=["X-API-Key", "X-Institution-Id", "Content-Type"])


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:12]
    if request.url.path.startswith("/preauth"):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > 65_536:
            return JSONResponse(status_code=413, content={"detail": "request body too large"},
                                headers={"X-Request-Id": rid})
    t0 = time.perf_counter()
    response = await call_next(request)
    response.headers.update({"X-Request-Id": rid, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                             "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
    log.info("%s %s -> %s %.1fms rid=%s", request.method, request.url.path, response.status_code,
             (time.perf_counter() - t0) * 1000, rid)
    return response


for r in (institutions.router, complaints.router, beacons.router, cases.router, review.router, graph.router, preauth.router):
    app.include_router(r)


@app.get("/healthz", tags=["ops"])
def healthz():
    return {"status": "ok", "version": VERSION}


@app.get("/readyz", tags=["ops"])
def readyz():
    health = verify_ledgers(get_state().audit, get_state().preauth_store)
    legacy = health["legacy"]
    preauth = health["preauth"]
    return {"ready": health["ready"], "audit_chain_intact": legacy["intact"], "preauth_chain_intact": preauth["intact"],
            "first_bad_seq": legacy["first_bad_seq"], "first_bad_paud_seq": preauth["first_bad_seq"]}


@app.get("/meta", tags=["ops"])
def meta():
    """Public console bootstrap. Sandbox accounts are exposed only in the sandbox environment."""
    out = {"name": "Trail", "version": VERSION, "environment": cfg.env}
    if not cfg.is_production:
        out["sandbox_accounts"] = [{"label": f"{p.user_id} · {p.role.value}", "key": k} for k, p in default_dev_users().items()
                                   if p.role.value != "institution_admin"]
    return out


_fe = Path(__file__).resolve().parents[2] / "frontend"
if _fe.exists():  # investigator console at /console/
    app.mount("/console", StaticFiles(directory=_fe, html=True), name="console")