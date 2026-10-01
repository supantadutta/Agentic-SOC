"""REST API: Wazuh alert ingestion, incident review, analyst approvals and metrics.

Authentication:
  * ``POST /api/v1/alerts/wazuh`` uses the ingest key (SOC_INGEST_API_KEY), sent by the
    Wazuh integration script as ``Authorization: Bearer <key>``.
  * Every other ``/api/v1`` endpoint needs an analyst key (SOC_ANALYST_API_KEYS); the
    analyst name recorded in the audit trail is derived from the key, never from input.

Interactive documentation is served at ``/docs``.
"""

from __future__ import annotations

import hmac
import json
import logging
import queue
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from agentic_soc.config.settings import Settings, get_settings
from agentic_soc.database.audit import verify_chain
from agentic_soc.database.models import (
    AgentAction,
    Alert,
    AuditEvent,
    HumanApproval,
    Incident,
    LLMDecision,
    PlaybookRun,
)
from agentic_soc.pipeline.metrics import collect_metrics
from agentic_soc.pipeline.orchestrator import OrchestratorError, SOCOrchestrator
from agentic_soc.pipeline.worker import AlertQueueWorker

log = logging.getLogger(__name__)


class ApprovalDecision(BaseModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=2000)


class DispositionRequest(BaseModel):
    disposition: Literal["true_positive", "false_positive", "benign"]
    comment: str | None = Field(default=None, max_length=2000)


def _bearer(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def _row(obj: Any, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = exclude or set()
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns if c.name not in exclude}


def create_app(
    settings: Settings | None = None, orchestrator: SOCOrchestrator | None = None, start_worker: bool = True
) -> FastAPI:
    settings = settings or get_settings()
    orchestrator = orchestrator or SOCOrchestrator.from_settings(settings)
    worker = AlertQueueWorker(orchestrator)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if start_worker:
            worker.start()
        yield
        worker.stop()

    app = FastAPI(title="Agentic SOC", version="0.1.0", lifespan=lifespan)
    app.state.orchestrator = orchestrator
    app.state.worker = worker
    db = orchestrator.db

    def require_ingest(
        authorization: str | None = Header(default=None), x_api_key: str | None = Header(default=None)
    ) -> None:
        expected = settings.ingest_api_key.get_secret_value() if settings.ingest_api_key else None
        supplied = _bearer(authorization, x_api_key)
        if not expected or not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest key")

    def require_analyst(
        authorization: str | None = Header(default=None), x_api_key: str | None = Header(default=None)
    ) -> str:
        supplied = _bearer(authorization, x_api_key)
        if supplied:
            for name, key in settings.analyst_api_keys.items():
                if hmac.compare_digest(supplied.encode(), key.get_secret_value().encode()):
                    return name
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid analyst key")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, Any]:
        with db.session() as session:
            session.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "queue_depth": worker.queue.qsize(),
            "execution_mode": settings.execution_mode,
            "llm_provider": settings.llm_provider,
        }

    # --- ingestion ---------------------------------------------------------------------------
    @app.post("/api/v1/alerts/wazuh", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_ingest)])
    async def ingest_wazuh_alert(request: Request, sync: bool = Query(default=False)) -> dict[str, Any]:
        body = await request.body()
        if len(body) > settings.max_alert_bytes:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "alert too large")
        try:
            raw = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid JSON: {exc}") from exc
        if not isinstance(raw, dict) or "rule" not in raw:
            raise HTTPException(422, "expected a Wazuh alert object with 'rule'")
        if sync:
            from starlette.concurrency import run_in_threadpool

            outcome = await run_in_threadpool(orchestrator.process_wazuh_alert, raw)
            return {"queued": False, "outcome": outcome.__dict__}
        try:
            depth = worker.submit(raw)
        except queue.Full as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "alert queue is full") from exc
        return {"queued": True, "queue_depth": depth}

    # --- incidents ---------------------------------------------------------------------------
    @app.get("/api/v1/incidents")
    def list_incidents(
        _analyst: str = Depends(require_analyst),
        status_filter: str | None = Query(default=None, alias="status"),
        limit: int = Query(default=50, le=500),
    ) -> list[dict[str, Any]]:
        with db.session() as session:
            query = select(Incident).order_by(Incident.last_seen.desc()).limit(limit)
            if status_filter:
                query = query.where(Incident.status == status_filter)
            return [_row(i) for i in session.execute(query).scalars()]

    @app.get("/api/v1/incidents/{incident_id}")
    def get_incident(incident_id: int, _analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        with db.session() as session:
            incident = session.get(Incident, incident_id)
            if incident is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

            def rows(model, *order):
                return [
                    _row(r)
                    for r in session.execute(
                        select(model).where(model.incident_id == incident_id).order_by(*order)
                    ).scalars()
                ]

            return {
                **_row(incident),
                "alerts": [
                    _row(a, {"raw"})
                    for a in session.execute(
                        select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.timestamp)
                    ).scalars()
                ],
                "llm_decisions": rows(LLMDecision, LLMDecision.id),
                "approvals": rows(HumanApproval, HumanApproval.id),
                "playbook_runs": rows(PlaybookRun, PlaybookRun.id),
                "agent_actions": rows(AgentAction, AgentAction.id),
            }

    @app.get("/api/v1/incidents/{incident_id}/audit")
    def get_audit(incident_id: int, _analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        with db.session() as session:
            events = [
                _row(e)
                for e in session.execute(
                    select(AuditEvent).where(AuditEvent.incident_id == incident_id).order_by(AuditEvent.seq)
                ).scalars()
            ]
            if not events:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no audit events for incident")
            check = verify_chain(session, incident_id)
        return {"incident_id": incident_id, "chain": check.__dict__, "events": events}

    @app.post("/api/v1/incidents/{incident_id}/disposition")
    def set_disposition(
        incident_id: int, body: DispositionRequest, analyst: str = Depends(require_analyst)
    ) -> dict[str, Any]:
        try:
            return orchestrator.set_disposition(incident_id, body.disposition, analyst, body.comment)
        except OrchestratorError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    # --- approvals ---------------------------------------------------------------------------
    @app.get("/api/v1/approvals")
    def list_approvals(
        _analyst: str = Depends(require_analyst),
        status_filter: str = Query(default="pending", alias="status"),
    ) -> list[dict[str, Any]]:
        with db.session() as session:
            return [
                _row(a)
                for a in session.execute(
                    select(HumanApproval)
                    .where(HumanApproval.status == status_filter)
                    .order_by(HumanApproval.risk_score.desc(), HumanApproval.requested_at)
                ).scalars()
            ]

    @app.post("/api/v1/approvals/{approval_id}/decision")
    def decide(approval_id: int, body: ApprovalDecision, analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        try:
            return orchestrator.decide_approval(approval_id, analyst, body.approve, body.comment)
        except OrchestratorError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    @app.post("/api/v1/playbook-runs/{run_id}/rollback")
    def rollback(run_id: int, analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        try:
            return orchestrator.rollback_run(run_id, analyst)
        except OrchestratorError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    # --- metrics ------------------------------------------------------------------------------
    @app.get("/api/v1/metrics")
    def metrics(_analyst: str = Depends(require_analyst)) -> dict[str, Any]:
        with db.session() as session:
            data = collect_metrics(session)
        data["queue"] = {"depth": worker.queue.qsize(), "processed": worker.processed, "failed": worker.failed}
        return data

    return app


def app_factory() -> FastAPI:
    """Entry point for ``uvicorn --factory agentic_soc.api.app:app_factory``."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
