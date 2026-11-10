"""Async analysis jobs + result cache.

An analysis takes 2-15 s, so the frontend submits a job (POST /api/jobs), gets a job id back at once and polls
GET /api/jobs/{job_id}. Finished reports are cached by normalised input for a short TTL, so resubmitting the same
URL / domain / message is answered straight from the report store. A submission whose input is already queued or
running joins that job instead of starting a second analysis.

Two backends with the same interface. JobManager keeps jobs and the cache in this process's memory, which is right
for a single API instance; restarting it forgets them (reports stay in the report store). RedisJobManager, used when
REDIS_URL is set, keeps them in Redis so any instance can answer for any job. The cache only holds report ids; reports
are always read back through `store.get`.

Signed-in users never share a cache entry or job, because each of them owns their own copy of a report.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from . import pipeline, shared, store
from .checks.fetcher import BlockedTarget, normalize_url
from .schemas import JobInfo, Report, RiskLevel

log = logging.getLogger(__name__)

WORKERS = max(1, int(os.getenv("JOB_WORKERS", "4")))
CACHE_TTL_URL = float(os.getenv("CACHE_TTL_URL", "600"))            # seconds, url + domain reports
CACHE_TTL_MESSAGE = float(os.getenv("CACHE_TTL_MESSAGE", "3600"))   # seconds, message reports
MAX_JOBS = 1000            # oldest finished jobs are evicted beyond this
MAX_CACHE_ENTRIES = 5000   # oldest cache entries are evicted beyond this

QUEUED, RUNNING, DONE, FAILED = "queued", "running", "done", "failed"
FINISHED = (DONE, FAILED)


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.UTC).isoformat(timespec="milliseconds")


def resolve_type(text: str, typ: str = "auto") -> str:
    """The input type the pipeline will use (same rule as `pipeline.analyze`)."""
    return pipeline.detect_type(text) if typ == "auto" else typ


def cache_key(text: str, typ: str = "auto", owner_id: str | None = None) -> str:
    """Normalised cache / de-dup key: owner (if signed in) + requested type + resolved type + normalised input."""
    resolved = resolve_type(text, typ)
    if resolved == "message":
        norm = hashlib.sha256(" ".join(text.split()).encode("utf-8")).hexdigest()
    else:
        try:
            norm = normalize_url(text)
        except BlockedTarget:
            norm = text.strip().lower()
    key = f"{typ}|{resolved}|{norm}"
    return f"user:{owner_id}|{key}" if owner_id else key


def _short_error(e: BaseException) -> str:
    """One line for the API response; the full traceback only goes to the server log."""
    msg = str(e).strip().splitlines()[0][:200] if str(e).strip() else ""
    return f"{type(e).__name__}: {msg}" if msg else type(e).__name__


class _Job:
    __slots__ = ("job_id", "key", "text", "req_type", "input_type", "owner_id", "status", "cached", "report_id", "error",
                 "created", "started", "finished", "_t0", "_t1")

    def __init__(self, key: str, text: str, req_type: str, input_type: str, owner_id: str | None = None):
        self.job_id = uuid.uuid4().hex[:12]
        self.owner_id = owner_id
        self.key = key
        self.text: str | None = text          # dropped once the job finishes
        self.req_type = req_type
        self.input_type = input_type
        self.status = QUEUED
        self.cached = False
        self.report_id: str | None = None
        self.error: str | None = None
        self.created = time.time()
        self.started: float | None = None
        self.finished: float | None = None
        self._t0 = time.monotonic()
        self._t1: float | None = None

    def info(self) -> JobInfo:
        end = self._t1 if self._t1 is not None else time.monotonic()
        return JobInfo(
            job_id=self.job_id, status=self.status, input_type=self.input_type,
            created_at=_iso(self.created),
            started_at=_iso(self.started) if self.started is not None else None,
            finished_at=_iso(self.finished) if self.finished is not None else None,
            elapsed_ms=int((end - self._t0) * 1000),
            report_id=self.report_id, error=self.error, cached=self.cached,
        )


class JobManager:
    """Thread-safe in-memory job registry + result cache, backed by a ThreadPoolExecutor."""

    def __init__(self, workers: int = WORKERS, ttl_url: float = CACHE_TTL_URL, ttl_message: float = CACHE_TTL_MESSAGE,
                 max_jobs: int = MAX_JOBS, max_cache_entries: int = MAX_CACHE_ENTRIES):
        self.ttl_url = ttl_url
        self.ttl_message = ttl_message
        self.max_jobs = max_jobs
        self.max_cache_entries = max_cache_entries
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="vigil-job")
        self._lock = threading.Lock()
        self._jobs: OrderedDict[str, _Job] = OrderedDict()               # job_id -> job, oldest first
        self._inflight: dict[str, _Job] = {}                             # cache key -> queued/running job
        self._cache: OrderedDict[str, tuple[str, float]] = OrderedDict()  # cache key -> (report_id, expires_at)

    # ------------------------------------------------------------------ cache ---------------------------
    def _ttl(self, input_type: str) -> float:
        return self.ttl_message if input_type == "message" else self.ttl_url

    def _cache_entry(self, key: str) -> str | None:
        """Live cached report id for `key` (caller holds the lock)."""
        hit = self._cache.get(key)
        if hit is None:
            return None
        if hit[1] <= time.monotonic():
            del self._cache[key]
            return None
        return hit[0]

    def _cache_put(self, key: str, input_type: str, report: Report) -> None:
        """Remember a finished report (caller holds the lock). Inconclusive results are often caused by a
        temporary network / feed outage, so they are not cached."""
        ttl = self._ttl(input_type)
        if ttl <= 0 or report.risk_level == RiskLevel.INCONCLUSIVE:
            return
        self._cache[key] = (report.report_id, time.monotonic() + ttl)
        self._cache.move_to_end(key)
        while len(self._cache) > self.max_cache_entries:
            self._cache.popitem(last=False)

    def _cached(self, key: str) -> Report | None:
        with self._lock:
            rid = self._cache_entry(key)
        if rid is None:
            return None
        report = store.get(rid)
        if report is None:                               # report vanished from the store: forget the entry
            with self._lock:
                if self._cache.get(key, (None,))[0] == rid:
                    del self._cache[key]
        return report

    def cached_report(self, text: str, typ: str = "auto", owner_id: str | None = None) -> Report | None:
        """Cached report for this input, or None (used by the synchronous /api/analyze)."""
        return self._cached(cache_key(text, typ, owner_id))

    def remember(self, text: str, typ: str, report: Report, owner_id: str | None = None) -> None:
        """Cache a report produced outside the job queue (the synchronous /api/analyze)."""
        key = cache_key(text, typ, owner_id)
        with self._lock:
            self._cache_put(key, resolve_type(text, typ), report)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------ jobs ----------------------------
    def _add(self, job: _Job) -> None:
        """Register a job, evicting the oldest finished ones beyond max_jobs (caller holds the lock)."""
        self._jobs[job.job_id] = job
        excess = len(self._jobs) - self.max_jobs
        if excess <= 0:
            return
        old = []
        for jid, j in self._jobs.items():
            if j.status in FINISHED:
                old.append(jid)
                if len(old) == excess:
                    break
        for jid in old:
            del self._jobs[jid]

    def _finish(self, job: _Job, status: str, report_id: str | None = None, error: str | None = None) -> None:
        """Caller holds the lock."""
        job.status, job.report_id, job.error = status, report_id, error
        job.finished, job._t1, job.text = time.time(), time.monotonic(), None
        if self._inflight.get(job.key) is job:
            del self._inflight[job.key]

    def _view(self, job: _Job) -> JobInfo:
        with self._lock:
            info = job.info()
        if info.status == DONE and info.report_id:
            info.report = store.get(info.report_id)
        return info

    def submit(self, text: str, typ: str = "auto", fresh: bool = False,
               on_new_work: Callable[[], None] | None = None, owner_id: str | None = None) -> JobInfo:
        """Queue an analysis, or answer it without new work.

        - same input already queued/running -> that job is returned (also with fresh=True: it is fresh anyway)
        - cached report (and not fresh)     -> a new job that is already `done` with `cached=True`
        - otherwise `on_new_work()` runs first (e.g. the rate limiter; if it raises, nothing is queued), then a
          new job is queued on the worker pool.
        """
        input_type = resolve_type(text, typ)
        key = cache_key(text, typ, owner_id)
        with self._lock:
            job = self._inflight.get(key)
        if job is not None:
            return self._view(job)

        if not fresh:
            report = self._cached(key)
            if report is not None:
                job = _Job(key, text, typ, input_type, owner_id)
                job.cached = True
                with self._lock:
                    self._finish(job, DONE, report_id=report.report_id)
                    job.started = job.created
                    self._add(job)
                    info = job.info()
                info.report = report
                return info

        with self._lock:
            job = self._inflight.get(key)              # another request may have queued it meanwhile
            if job is None:
                if on_new_work is not None:
                    on_new_work()
                job = _Job(key, text, typ, input_type, owner_id)
                self._add(job)
                self._inflight[key] = job
                self._pool.submit(self._run, job)
        return self._view(job)

    def _run(self, job: _Job) -> None:
        with self._lock:
            job.status, job.started = RUNNING, time.time()
            text, typ = job.text or "", job.req_type
        try:
            report = pipeline.analyze(text, typ, owner_id=job.owner_id)
        except Exception as e:
            log.exception("analysis job %s failed", job.job_id)
            with self._lock:
                self._finish(job, FAILED, error=_short_error(e))
            return
        with self._lock:                                 # cache + finish atomically: no window for a duplicate run
            self._cache_put(job.key, job.input_type, report)
            self._finish(job, DONE, report_id=report.report_id)

    def get(self, job_id: str, viewer_id: str | None = None) -> JobInfo | None:
        """Job by id (with the full report when done), or None if unknown, evicted or another user's."""
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None or job.owner_id not in (None, viewer_id):
            return None
        return self._view(job)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)


JOB_TTL = int(os.getenv("JOB_TTL_SECONDS", "3600"))              # how long a job can be polled
INFLIGHT_TTL = int(os.getenv("JOB_INFLIGHT_TTL_SECONDS", "900"))  # longest an analysis may hold its de-dup marker

_RELEASE = """if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0"""


class QueueUnavailable(RuntimeError):
    """The shared job state (Redis) couldn't be reached."""


def _guarded(method):
    def wrapper(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except shared.RedisError as e:
            raise QueueUnavailable(str(e)) from e
    wrapper.__doc__ = method.__doc__
    return wrapper


class RedisJobManager:
    """Jobs, the de-dup marker and the result cache in Redis, shared by every API instance.

    Each analysis still runs in a worker thread of the instance that accepted it. If that instance dies mid-analysis,
    the job stays `running` until it expires, and the same input can be submitted again once its de-dup marker times
    out (JOB_INFLIGHT_TTL_SECONDS).
    """

    def __init__(self, redis_client, workers: int = WORKERS, ttl_url: float = CACHE_TTL_URL,
                 ttl_message: float = CACHE_TTL_MESSAGE, job_ttl: int = JOB_TTL, inflight_ttl: int = INFLIGHT_TTL):
        self._r = redis_client
        self.ttl_url, self.ttl_message = ttl_url, ttl_message
        self.job_ttl, self.inflight_ttl = job_ttl, inflight_ttl
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="vigil-job")

    @staticmethod
    def _job_key(job_id: str) -> str:
        return shared.key("job", job_id)

    @staticmethod
    def _cache_key(key: str) -> str:
        return shared.key("cache", shared.digest(key))

    @staticmethod
    def _inflight_key(key: str) -> str:
        return shared.key("inflight", shared.digest(key))

    def _ttl(self, input_type: str) -> float:
        return self.ttl_message if input_type == "message" else self.ttl_url

    def _cache_put(self, key: str, input_type: str, report: Report, pipe=None) -> None:
        ttl = self._ttl(input_type)
        if ttl <= 0 or report.risk_level == RiskLevel.INCONCLUSIVE:   # often a temporary outage: don't repeat it
            return
        (pipe or self._r).set(self._cache_key(key), report.report_id, px=int(ttl * 1000))

    def _cached(self, key: str) -> Report | None:
        rid = self._r.get(self._cache_key(key))
        if rid is None:
            return None
        report = store.get(rid)
        if report is None:                               # report vanished from the store: forget the entry
            self._r.delete(self._cache_key(key))
        return report

    def _save(self, job_id: str, fields: dict, pipe=None) -> None:
        target = pipe or self._r
        target.hset(self._job_key(job_id), mapping={k: "" if v is None else str(v) for k, v in fields.items()})
        target.expire(self._job_key(job_id), self.job_ttl)

    def _load(self, job_id: str) -> tuple[JobInfo, str] | None:
        """The job and its owner ("" for a guest), or None if unknown or expired."""
        h = self._r.hgetall(self._job_key(job_id))
        if not h:
            return None
        created = float(h["created"])
        started = float(h["started"]) if h.get("started") else None
        finished = float(h["finished"]) if h.get("finished") else None
        info = JobInfo(job_id=job_id, status=h["status"], input_type=h["input_type"], created_at=_iso(created),
                       started_at=_iso(started) if started is not None else None,
                       finished_at=_iso(finished) if finished is not None else None,
                       elapsed_ms=int(((finished or time.time()) - created) * 1000),
                       report_id=h.get("report_id") or None, error=h.get("error") or None, cached=h.get("cached") == "1")
        return info, h.get("owner", "")

    def _view(self, job_id: str) -> JobInfo | None:
        loaded = self._load(job_id)
        if loaded is None:
            return None
        info = loaded[0]
        if info.status == DONE and info.report_id:
            info.report = store.get(info.report_id)
        return info

    @_guarded
    def cached_report(self, text: str, typ: str = "auto", owner_id: str | None = None) -> Report | None:
        return self._cached(cache_key(text, typ, owner_id))

    @_guarded
    def remember(self, text: str, typ: str, report: Report, owner_id: str | None = None) -> None:
        self._cache_put(cache_key(text, typ, owner_id), resolve_type(text, typ), report)

    @_guarded
    def clear_cache(self) -> None:
        for k in self._r.scan_iter(match=shared.key("cache", "*")):
            self._r.delete(k)

    @_guarded
    def submit(self, text: str, typ: str = "auto", fresh: bool = False,
               on_new_work: Callable[[], None] | None = None, owner_id: str | None = None) -> JobInfo:
        """Same contract as JobManager.submit, across every instance: one in-flight job per input."""
        input_type = resolve_type(text, typ)
        key = cache_key(text, typ, owner_id)
        inflight = self._inflight_key(key)
        for _ in range(2):                               # a second pass covers a marker that expired mid-check
            running = self._r.get(inflight)
            if running and (info := self._view(running)) is not None:
                return info
            if not fresh and (report := self._cached(key)) is not None:
                job_id, now = uuid.uuid4().hex[:12], time.time()
                self._save(job_id, {"status": DONE, "input_type": input_type, "owner": owner_id, "cached": 1,
                                    "report_id": report.report_id, "created": now, "started": now, "finished": now})
                info = self._view(job_id)
                info.report = report
                return info
            if on_new_work is not None:
                on_new_work()
                on_new_work = None                       # charge the rate limit once, even on a second pass
            job_id = uuid.uuid4().hex[:12]
            self._save(job_id, {"status": QUEUED, "input_type": input_type, "owner": owner_id, "cached": 0,
                                "created": time.time()})
            if self._r.set(inflight, job_id, nx=True, ex=self.inflight_ttl):
                self._pool.submit(self._run, job_id, key, text, typ, input_type, owner_id)
                return self._view(job_id)
            self._r.delete(self._job_key(job_id))        # another instance queued it first: join that job
        raise QueueUnavailable("could not queue the analysis")

    def _run(self, job_id: str, key: str, text: str, typ: str, input_type: str, owner_id: str | None) -> None:
        try:
            try:
                self._save(job_id, {"status": RUNNING, "started": time.time()})
                report = pipeline.analyze(text, typ, owner_id=owner_id)
            except shared.RedisError:
                raise
            except Exception as e:
                log.exception("analysis job %s failed", job_id)
                self._save(job_id, {"status": FAILED, "error": _short_error(e), "finished": time.time()})
                return
            pipe = self._r.pipeline(transaction=True)    # cache + finish together: no window for a duplicate run
            self._cache_put(key, input_type, report, pipe)
            self._save(job_id, {"status": DONE, "report_id": report.report_id, "finished": time.time()}, pipe)
            pipe.execute()
        except shared.RedisError:
            log.exception("job %s lost its connection to Redis", job_id)
        finally:
            try:
                self._r.eval(_RELEASE, 1, self._inflight_key(key), job_id)
            except shared.RedisError:
                log.warning("could not release the de-dup marker for job %s; it expires on its own", job_id)

    @_guarded
    def get(self, job_id: str, viewer_id: str | None = None) -> JobInfo | None:
        """Job by id (with the full report when done), or None if unknown, expired or another user's."""
        loaded = self._load(job_id)
        if loaded is None or loaded[1] not in ("", viewer_id or ""):
            return None
        return self._view(job_id)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)


BACKEND = "redis" if shared.client() is not None else "memory"
manager = RedisJobManager(shared.client()) if BACKEND == "redis" else JobManager()


def submit(text: str, typ: str = "auto", fresh: bool = False,
           on_new_work: Callable[[], None] | None = None, owner_id: str | None = None) -> JobInfo:
    return manager.submit(text, typ, fresh=fresh, on_new_work=on_new_work, owner_id=owner_id)


def get(job_id: str, viewer_id: str | None = None) -> JobInfo | None:
    return manager.get(job_id, viewer_id)


def cached_report(text: str, typ: str = "auto", owner_id: str | None = None) -> Report | None:
    return manager.cached_report(text, typ, owner_id)


def remember(text: str, typ: str, report: Report, owner_id: str | None = None) -> None:
    manager.remember(text, typ, report, owner_id)
