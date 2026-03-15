"""
Phase 2 — Continuous Monitoring Engine.

Schedules recurring security scans at configurable intervals.
Uses APScheduler when available; falls back to asyncio-based naive scheduler.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)

_APSCHEDULER_AVAILABLE = False
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore[import-not-found]
    from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import-not-found]
    _APSCHEDULER_AVAILABLE = True
except Exception:
    pass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class MonitorJob:
    """Represents a single continuous monitoring job."""

    def __init__(
        self,
        job_id: str,
        target: str,
        scan_types: List[str],
        interval_seconds: int,
        created_by: str = "system",
        alert_on_new_critical: bool = True,
    ):
        self.job_id = job_id
        self.target = target
        self.scan_types = scan_types
        self.interval_seconds = interval_seconds
        self.created_by = created_by
        self.alert_on_new_critical = alert_on_new_critical
        self.created_at = datetime.utcnow().isoformat()
        self.last_run: Optional[str] = None
        self.next_run: Optional[str] = None
        self.run_count = 0
        self.status = "active"
        self.last_findings_count = 0
        self.alerts: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "scan_types": self.scan_types,
            "interval_seconds": self.interval_seconds,
            "created_by": self.created_by,
            "alert_on_new_critical": self.alert_on_new_critical,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "run_count": self.run_count,
            "status": self.status,
            "last_findings_count": self.last_findings_count,
            "recent_alerts": self.alerts[-5:],
        }


# ---------------------------------------------------------------------------
# Monitor engine
# ---------------------------------------------------------------------------

class ContinuousMonitor:
    """
    Continuous monitoring engine that schedules and tracks recurring scans.

    Usage::

        monitor = ContinuousMonitor(scan_callback=async_perform_scan)
        await monitor.start()
        job_id = await monitor.schedule(
            target="https://example.com",
            scan_types=["web"],
            interval_seconds=3600,
        )
        ...
        await monitor.stop()
    """

    def __init__(self, scan_callback: Optional[Callable[..., Coroutine[Any, Any, Any]]] = None):
        self._jobs: Dict[str, MonitorJob] = {}
        self._callback = scan_callback
        self._scheduler: Optional[Any] = None
        self._asyncio_tasks: Dict[str, asyncio.Task] = {}
        self._running = False

    async def start(self) -> None:
        """Start the monitoring engine."""
        self._running = True
        if _APSCHEDULER_AVAILABLE:
            self._scheduler = AsyncIOScheduler()
            self._scheduler.start()
            logger.info("ContinuousMonitor started with APScheduler")
        else:
            logger.info("ContinuousMonitor started (asyncio fallback mode)")

    async def stop(self) -> None:
        """Stop the monitoring engine and cancel all active jobs."""
        self._running = False
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
        for task in self._asyncio_tasks.values():
            task.cancel()
        self._asyncio_tasks.clear()
        logger.info("ContinuousMonitor stopped")

    async def schedule(
        self,
        target: str,
        scan_types: List[str],
        interval_seconds: int,
        created_by: str = "system",
        alert_on_new_critical: bool = True,
    ) -> str:
        """
        Schedule a recurring scan job.

        Args:
            target: Scan target (URL, IP, domain).
            scan_types: List of scan type strings.
            interval_seconds: Minimum 60 seconds between runs.
            created_by: Requesting user identifier.
            alert_on_new_critical: Emit alert when new critical findings appear.

        Returns:
            job_id (str)
        """
        job_id = secrets.token_urlsafe(12)
        job = MonitorJob(
            job_id=job_id,
            target=target,
            scan_types=scan_types,
            interval_seconds=max(60, interval_seconds),
            created_by=created_by,
            alert_on_new_critical=alert_on_new_critical,
        )
        next_run_dt = datetime.utcnow() + timedelta(seconds=job.interval_seconds)
        job.next_run = next_run_dt.isoformat()
        self._jobs[job_id] = job

        if _APSCHEDULER_AVAILABLE and self._scheduler is not None:
            self._scheduler.add_job(
                self._run_job,
                trigger=IntervalTrigger(seconds=job.interval_seconds),
                id=job_id,
                args=[job_id],
                next_run_time=next_run_dt,
            )
        else:
            task = asyncio.create_task(self._asyncio_loop(job_id))
            self._asyncio_tasks[job_id] = task

        logger.info(
            "Scheduled monitoring job %s for %s every %ds",
            job_id, target, job.interval_seconds,
        )
        return job_id

    async def _asyncio_loop(self, job_id: str) -> None:
        """Asyncio-based fallback scheduler loop."""
        while self._running and job_id in self._jobs:
            job = self._jobs[job_id]
            if job.status != "active":
                break
            await asyncio.sleep(job.interval_seconds)
            if self._running and job_id in self._jobs:
                await self._run_job(job_id)

    async def _run_job(self, job_id: str) -> None:
        """Execute a single monitoring job run."""
        job = self._jobs.get(job_id)
        if job is None or job.status != "active":
            return

        now = datetime.utcnow()
        job.last_run = now.isoformat()
        job.run_count += 1
        job.next_run = (now + timedelta(seconds=job.interval_seconds)).isoformat()
        logger.info(
            "Running monitoring job %s for %s (run #%d)",
            job_id, job.target, job.run_count,
        )

        if self._callback is not None:
            try:
                result = await self._callback(job.target, job.scan_types)
                findings_count = (
                    result.get("findings_count", 0) if isinstance(result, dict) else 0
                )
                job.last_findings_count = findings_count
                # Generate alert if threshold crossed and new criticals detected
                if job.alert_on_new_critical and isinstance(result, dict):
                    criticals = result.get("critical_count", 0)
                    if criticals > 0:
                        alert = {
                            "job_id": job_id,
                            "target": job.target,
                            "run": job.run_count,
                            "critical_findings": criticals,
                            "ts": now.isoformat(),
                            "message": f"{criticals} critical finding(s) detected for {job.target}",
                        }
                        job.alerts.append(alert)
                        logger.warning("MONITOR ALERT: %s", alert["message"])
            except Exception as exc:
                logger.warning("Monitoring job %s callback error: %s", job_id, exc)

    # ------------------------------------------------------------------
    # Lifecycle management
    # ------------------------------------------------------------------

    def pause(self, job_id: str) -> bool:
        """Pause a monitoring job."""
        job = self._jobs.get(job_id)
        if job is None:
            return False
        job.status = "paused"
        if _APSCHEDULER_AVAILABLE and self._scheduler is not None:
            try:
                self._scheduler.pause_job(job_id)
            except Exception:
                pass
        return True

    def resume(self, job_id: str) -> bool:
        """Resume a paused monitoring job."""
        job = self._jobs.get(job_id)
        if job is None:
            return False
        job.status = "active"
        if _APSCHEDULER_AVAILABLE and self._scheduler is not None:
            try:
                self._scheduler.resume_job(job_id)
            except Exception:
                pass
        return True

    def cancel(self, job_id: str) -> bool:
        """Cancel and remove a monitoring job."""
        job = self._jobs.pop(job_id, None)
        if job is None:
            return False
        job.status = "cancelled"
        if _APSCHEDULER_AVAILABLE and self._scheduler is not None:
            try:
                self._scheduler.remove_job(job_id)
            except Exception:
                pass
        if job_id in self._asyncio_tasks:
            self._asyncio_tasks[job_id].cancel()
            del self._asyncio_tasks[job_id]
        return True

    def list_jobs(self) -> List[Dict[str, Any]]:
        """Return all monitoring jobs as dicts."""
        return [j.to_dict() for j in self._jobs.values()]

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return a single job dict by ID, or None."""
        job = self._jobs.get(job_id)
        return job.to_dict() if job else None

    @property
    def active_job_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status == "active")
