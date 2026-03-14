from datetime import datetime, timedelta
import logging
import subprocess
import threading


logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter for scan operations."""

    def __init__(self, max_scans_per_hour=10, cooldown_seconds=300):
        self.max_scans_per_hour = max_scans_per_hour
        self.cooldown_seconds = cooldown_seconds
        self.scan_timestamps = []
        self.last_scan_time = None

    def can_scan(self):
        now = datetime.now()

        if self.last_scan_time:
            elapsed = (now - self.last_scan_time).total_seconds()
            if elapsed < self.cooldown_seconds:
                logger.warning(
                    "Scan cooldown active. Wait %ss more",
                    int(self.cooldown_seconds - elapsed),
                )
                return (
                    False,
                    f"Cooldown active. Try again in {int(self.cooldown_seconds - elapsed)}s",
                )

        one_hour_ago = now - timedelta(hours=1)
        recent_scans = [ts for ts in self.scan_timestamps if ts > one_hour_ago]
        if len(recent_scans) >= self.max_scans_per_hour:
            logger.warning("Rate limit reached: %s scans/hour", self.max_scans_per_hour)
            return False, f"Rate limit reached ({self.max_scans_per_hour} scans/hour)"

        return True, None

    def record_scan(self):
        now = datetime.now()
        self.scan_timestamps.append(now)
        self.last_scan_time = now

        one_hour_ago = now - timedelta(hours=1)
        self.scan_timestamps = [ts for ts in self.scan_timestamps if ts > one_hour_ago]
        logger.info("Scan recorded. Total in last hour: %s", len(self.scan_timestamps))


class PerClientRateLimiter:
    """Per-session rate limiter so one client cannot block others."""

    def __init__(self, max_scans_per_hour=10, cooldown_seconds=300):
        self._max_scans_per_hour = max_scans_per_hour
        self._cooldown_seconds = cooldown_seconds
        self._clients: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def _get(self, sid: str) -> RateLimiter:
        with self._lock:
            if sid not in self._clients:
                self._clients[sid] = RateLimiter(
                    max_scans_per_hour=self._max_scans_per_hour,
                    cooldown_seconds=self._cooldown_seconds,
                )
            return self._clients[sid]

    def can_scan(self, sid: str):
        return self._get(sid).can_scan()

    def record_scan(self, sid: str):
        self._get(sid).record_scan()

    def remove_client(self, sid: str):
        with self._lock:
            self._clients.pop(sid, None)


class ClientJobRegistry:
    """Track active scan/report jobs per connected client."""

    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()
        self._processes = {}

    def start(self, sid: str, job_type: str, details=None) -> bool:
        with self._lock:
            key = (sid, job_type)
            job = self._jobs.get(key)
            if job and job.get("status") == "running":
                return False
            self._jobs[key] = {
                "status": "running",
                "started_at": datetime.now().isoformat(),
                "cancel_requested": False,
                "details": details or {},
            }
            return True

    def complete(self, sid: str, job_type: str, status="completed", details=None):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key, {})
            current.update({"status": status, "finished_at": datetime.now().isoformat()})
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current

    def update(self, sid: str, job_type: str, details=None, **fields):
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current:
                return
            current.update(fields)
            if details:
                merged = dict(current.get("details", {}))
                merged.update(details)
                current["details"] = merged
            self._jobs[key] = current

    def cancel(self, sid: str, job_type: str) -> bool:
        with self._lock:
            key = (sid, job_type)
            current = self._jobs.get(key)
            if not current or current.get("status") != "running":
                return False
            current["cancel_requested"] = True
            current["status"] = "cancelling"
            current["cancel_requested_at"] = datetime.now().isoformat()
            self._jobs[key] = current

            process = self._processes.get(key)
            if process and process.poll() is None:
                try:
                    process.terminate()
                except Exception:
                    logger.exception("Failed to terminate subprocess for %s", key)
            return True

    def is_cancelled(self, sid: str, job_type: str) -> bool:
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return bool(job and job.get("cancel_requested"))

    def attach_process(self, sid: str, job_type: str, process: subprocess.Popen):
        with self._lock:
            self._processes[(sid, job_type)] = process

    def clear_process(self, sid: str, job_type: str):
        with self._lock:
            self._processes.pop((sid, job_type), None)

    def get(self, sid: str, job_type: str):
        with self._lock:
            job = self._jobs.get((sid, job_type))
            return dict(job) if job else None

    def mark_disconnected(self, sid: str):
        with self._lock:
            for key, job in list(self._jobs.items()):
                if key[0] != sid:
                    continue
                if job.get("status") == "running":
                    job["disconnected"] = True
                    job["disconnected_at"] = datetime.now().isoformat()
                    self._jobs[key] = job
                else:
                    self._jobs.pop(key, None)

    def clear_if_disconnected(self, sid: str, job_type: str):
        with self._lock:
            key = (sid, job_type)
            job = self._jobs.get(key)
            if job and job.get("disconnected"):
                self._jobs.pop(key, None)
            self._processes.pop(key, None)


def ensure_job_not_cancelled(job_registry, sid: str, job_type: str):
    """Stop the current workflow if cancellation was requested."""
    if job_registry.is_cancelled(sid, job_type):
        raise RuntimeError(f"{job_type} cancelled")


def run_cancellable_command(
    job_registry,
    cmd,
    sid=None,
    job_type=None,
    timeout=None,
):
    """Run a subprocess that can be cancelled via the job registry."""
    start = datetime.now()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if sid and job_type:
        job_registry.attach_process(sid, job_type, process)

    try:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                if timeout is not None and (datetime.now() - start).total_seconds() > timeout:
                    process.kill()
                    stdout, stderr = process.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr)
                if sid and job_type and job_registry.is_cancelled(sid, job_type):
                    process.terminate()
                    try:
                        stdout, stderr = process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                    raise RuntimeError(f"{job_type} cancelled")

        return subprocess.CompletedProcess(
            args=cmd, returncode=process.returncode, stdout=stdout, stderr=stderr
        )
    finally:
        if sid and job_type:
            job_registry.clear_process(sid, job_type)
