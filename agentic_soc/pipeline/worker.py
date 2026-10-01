"""Single background worker that processes queued alerts in arrival order."""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any

from agentic_soc.pipeline.orchestrator import SOCOrchestrator

log = logging.getLogger(__name__)


class AlertQueueWorker:
    def __init__(self, orchestrator: SOCOrchestrator, maxsize: int = 10_000) -> None:
        self.orchestrator = orchestrator
        self.queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=maxsize)
        self._thread: threading.Thread | None = None
        self.processed = 0
        self.failed = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="alert-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        if self._thread and self._thread.is_alive():
            self.queue.put(None)
            self._thread.join(timeout)

    def submit(self, raw: dict[str, Any]) -> int:
        """Queue an alert; raises queue.Full when the backlog is at capacity."""
        self.queue.put_nowait(raw)
        return self.queue.qsize()

    def _run(self) -> None:
        while True:
            raw = self.queue.get()
            try:
                if raw is None:
                    return
                self.orchestrator.process_wazuh_alert(raw)
                self.processed += 1
            except Exception:  # noqa: BLE001 - one bad alert must not stop the worker
                self.failed += 1
                log.exception("failed to process alert %s", (raw or {}).get("id"))
            finally:
                self.queue.task_done()
