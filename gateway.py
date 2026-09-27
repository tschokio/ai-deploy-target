#!/usr/bin/env python3
"""ai-deploy target gateway (Phase 8, trust level 1 DEPLOY).

Installed on the target as /usr/local/lib/ai-deploy/gateway and referenced by a
forced-command authorized_keys entry:

    restrict,command="/usr/local/lib/ai-deploy/gateway" ssh-ed25519 AAAA... ai-remote-<machine>

It is the only thing a deploy key can execute. The operation name arrives in
SSH_ORIGINAL_COMMAND (exactly one of status|deploy|restart|health|logs|rollback|history),
the request is a small JSON object on stdin, and every answer is a bounded JSON
object on stdout with a schema version. The gateway never runs a shell: every
command is an explicit argv, every path/service comes from the target-owned
allowlist /etc/ai-deploy/apps.json, and a deployment accepts a full 40-hex
commit SHA only.

Deployment model: a target-local bare mirror (git clone --mirror on first use,
git remote update --prune afterwards) -> exact SHA extracted into
releases/<UTC ts>-<sha7>/ -> fixed build argv -> atomic `current` symlink
switch -> restart exactly one allowlisted unit -> health check. A failed build
leaves `current` untouched; a failed health check switches back to the previous
release, restarts and re-checks it and reports {result: "rolled_back"}.

Environment overrides (tests / unusual installs):
  AI_DEPLOY_CONFIG      apps.json path            (default /etc/ai-deploy/apps.json)
  AI_DEPLOY_SYSTEMCTL   systemctl path            (default /usr/bin/systemctl)
  AI_DEPLOY_SUDO        sudo path                 (default sudo)
  AI_DEPLOY_JOURNALCTL  journalctl path           (default journalctl)
  AI_DEPLOY_TAR         tar path                  (default tar)
  AI_DEPLOY_GIT         git path                  (default git)
  AI_DEPLOY_COMPOSE_UP  compose wrapper path      (default /usr/local/lib/ai-deploy/compose-up)
  AI_DEPLOY_RESTORECON  restorecon path           (default /usr/sbin/restorecon)
  AI_DEPLOY_SELINUX_FORCE=1 forces the relabel step even without /sys/fs/selinux/enforce
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def _package_version():
    """Shared package version: sibling VERSION when installed, else a constant."""
    try:
        text = (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.2.2"
    return text or "0.2.2"


VERSION = _package_version()
SCHEMA = "ai-deploy/1"
PROG = "ai-deploy-gateway"

OPS = ("status", "deploy", "restart", "health", "logs", "rollback", "history")
REQUEST_FIELDS = ("app", "sha", "ai", "lines", "since", "to")
REQUEST_CAP = 8 * 1024
RESPONSE_CAP = 256 * 1024
LOGS_CAP = 128 * 1024
BUILD_OUTPUT_CAP = 16 * 1024
DETAIL_CAP = 2000
HISTORY_MAX_ENTRIES = 500
HISTORY_MAX_BYTES = 1024 * 1024
HISTORY_READ_CAP = 4 * 1024 * 1024
HISTORY_ALL_APPS_LIMIT = 20
KEEP_DEFAULT = 5
BUILD_TIMEOUT_DEFAULT = 600
FETCH_TIMEOUT = 600
RESTART_TIMEOUT = 90
# The compose wrapper itself bounds docker at 900 s; allow a little longer here so the
# gateway does not kill a build the wrapper would still accept.
COMPOSE_RESTART_TIMEOUT = 960
HEALTH_TOTAL_DEFAULT = 30.0
HEALTH_INTERVAL_DEFAULT = 1.0
HEALTH_STATUS_TIMEOUT = 3.0
STATUS_BUDGET = 12.0
RELABEL_TIMEOUT = 120
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

KIND_DEFAULT = "service"
KINDS = ("service", "static", "compose")
COMPOSE_FILE_DEFAULT = "compose.yml"
COMPOSE_UP_DEFAULT = "/usr/local/lib/ai-deploy/compose-up"
RESTORECON_DEFAULT = "/usr/sbin/restorecon"
SELINUX_ENFORCE = "/sys/fs/selinux/enforce"

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
APP_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
RELEASE_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{7}(-[0-9]+)?$")
SINCE_RE = re.compile(
    r"^(?:[0-9]{1,4}[smhdw]|"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?|"
    r"today|yesterday|now)$"
)
UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,127}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

# --------------------------------------------------------------------------
# redaction: logs, build output and error details never carry obvious secrets


REDACTIONS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "<redacted-private-key>"),
    (re.compile(r"(?i)\b(authorization)\b\s*[:=][^\r\n]*"), r"\1: <redacted>"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 <redacted>"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|credential|passphrase)\b\s*[:=]\s*\S+"),
     r"\1=<redacted>"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|"
                r"sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,})\b"),
     "<redacted-token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "<redacted-jwt>"),
)


def redact(text):
    if not text:
        return text
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def tail_text(text, limit):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[-limit:]


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class GatewayError(Exception):
    """Explicit error code plus a bounded, redacted detail string."""

    def __init__(self, code, detail=""):
        super().__init__(detail or code)
        self.code = code
        self.detail = redact(str(detail))[:DETAIL_CAP]


# --------------------------------------------------------------------------
# bounded process execution (never a shell, always a killed process group)


class RunResult:
    __slots__ = ("rc", "out", "err", "out_bytes", "err_bytes", "out_kept", "error", "timed_out")

    def __init__(self):
        self.rc = None
        self.out = ""
        self.err = ""
        self.out_bytes = 0
        self.err_bytes = 0
        self.out_kept = 0
        self.error = None
        self.timed_out = False

    @property
    def ok(self):
        return self.error is None and self.rc == 0

    def detail(self, limit=DETAIL_CAP):
        if self.error:
            return self.error
        text = (self.err or self.out or "").strip()
        if self.rc not in (None, 0):
            text = f"exit {self.rc}: {text}" if text else f"exit {self.rc}"
        return redact(tail_text(text, limit))


def _read_capped(pipe, cap, tail, sink):
    data = bytearray()
    total = 0
    while True:
        try:
            chunk = pipe.read(65536)
        except (OSError, ValueError):
            break
        if not chunk:
            break
        total += len(chunk)
        if cap <= 0:
            continue
        if tail:
            data.extend(chunk)
            if len(data) > cap:
                del data[: len(data) - cap]
        elif len(data) < cap:
            data.extend(chunk[: cap - len(data)])
    sink["data"] = bytes(data)
    sink["total"] = total


def _kill_group(proc):
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError, OSError):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def run_capped(argv, timeout, cwd=None, env=None, cap=16384, tail=False):
    """Run argv as its own process group, keep at most cap bytes of each stream."""
    result = RunResult()
    try:
        proc = subprocess.Popen(
            [str(part) for part in argv],
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    out_sink = {"data": b"", "total": 0}
    err_sink = {"data": b"", "total": 0}
    readers = [
        threading.Thread(target=_read_capped, args=(proc.stdout, cap, tail, out_sink), daemon=True),
        threading.Thread(target=_read_capped, args=(proc.stderr, cap, tail, err_sink), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        result.rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        result.timed_out = True
        _kill_group(proc)
        try:
            result.rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            result.rc = -9
    for reader in readers:
        reader.join(2)
    result.out_bytes = out_sink["total"]
    result.err_bytes = err_sink["total"]
    result.out_kept = len(out_sink["data"])
    result.out = out_sink["data"].decode("utf-8", "replace")
    result.err = err_sink["data"].decode("utf-8", "replace")
    if result.timed_out:
        result.error = f"timeout after {timeout}s"
    return result


def extract_archive(mirror, sha, release_dir, env, timeout=300):
    """git archive SHA | tar -x -C release_dir, without ever starting a shell."""
    tar = os.environ.get("AI_DEPLOY_TAR") or "tar"
    git = os.environ.get("AI_DEPLOY_GIT") or "git"
    result = RunResult()
    try:
        producer = subprocess.Popen(
            [git, f"--git-dir={mirror}", "archive", sha],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True,
        )
    except OSError as exc:
        result.error = f"git archive: {type(exc).__name__}: {exc}"
        return result
    try:
        consumer = subprocess.Popen(
            [tar, "-x", "-C", str(release_dir)],
            stdin=producer.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True,
        )
    except OSError as exc:
        _kill_group(producer)
        producer.wait()
        result.error = f"tar: {type(exc).__name__}: {exc}"
        return result
    producer.stdout.close()
    err_sinks = [{"data": b"", "total": 0}, {"data": b"", "total": 0}]
    threads = [
        threading.Thread(target=_read_capped, args=(producer.stderr, 8192, False, err_sinks[0]), daemon=True),
        threading.Thread(target=_read_capped, args=(consumer.stderr, 8192, False, err_sinks[1]), daemon=True),
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    for proc in (consumer, producer):
        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(consumer)
            _kill_group(producer)
            break
    for thread in threads:
        thread.join(2)
    consumer_rc = consumer.poll()
    producer_rc = producer.poll()
    result.timed_out = timed_out
    result.rc = consumer_rc if consumer_rc not in (None, 0) else producer_rc
    result.err = err_sinks[1]["data"].decode("utf-8", "replace") or err_sinks[0]["data"].decode("utf-8", "replace")
    if timed_out:
        result.error = f"archive extraction timeout after {timeout}s"
    elif consumer_rc != 0:
        result.error = f"tar exited {consumer_rc}"
    elif producer_rc != 0:
        result.error = f"git archive exited {producer_rc}"
    return result


# --------------------------------------------------------------------------
# configuration (/etc/ai-deploy/apps.json, target-owned and authoritative)


def config_path():
    return Path(os.environ.get("AI_DEPLOY_CONFIG") or "/etc/ai-deploy/apps.json")


def _validate_health(app, health):
    if health is None:
        return None
    if not isinstance(health, dict):
        raise GatewayError("config_error", f"app {app}: health must be an object")
    kind = health.get("type")
    if kind == "http":
        url = health.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise GatewayError("config_error", f"app {app}: health.url must be an http(s) URL")
    elif kind == "command":
        argv = health.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(part, str) and part for part in argv):
            raise GatewayError("config_error", f"app {app}: health.argv must be a non-empty argv list")
    else:
        raise GatewayError("config_error", f"app {app}: health.type must be http or command")
    out = {"type": kind}
    for key in ("url", "argv"):
        if key in health:
            out[key] = health[key]
    for key in ("timeout", "totalSeconds", "interval"):
        if key in health:
            try:
                out[key] = float(health[key])
            except (TypeError, ValueError):
                raise GatewayError("config_error", f"app {app}: health.{key} must be a number")
    return out


def _path_inside(root, candidate):
    """True when an absolute candidate path is lexically at or inside root."""
    root_norm = os.path.normpath(root).rstrip("/") or "/"
    candidate_norm = os.path.normpath(candidate)
    if root_norm == "/":
        return candidate_norm.startswith("/")
    return candidate_norm == root_norm or candidate_norm.startswith(root_norm + "/")


def _validate_build(name, raw_build):
    """Normalize build to a list of argv lists (schema 2) or one argv list (schema 1)."""
    if raw_build is None:
        return []
    if not isinstance(raw_build, list):
        raise GatewayError("config_error", f"app {name}: build must be an argv list or a list of argv lists")
    if not raw_build:
        return []
    if all(isinstance(step, list) for step in raw_build):
        steps = []
        for step in raw_build:
            if not step or not all(isinstance(part, str) and part for part in step):
                raise GatewayError("config_error",
                                   f"app {name}: each build step must be a non-empty argv list")
            steps.append(list(step))
        return steps
    if all(isinstance(part, str) and part for part in raw_build):
        return [list(raw_build)]
    raise GatewayError("config_error",
                       f"app {name}: build must be an argv list or a list of argv lists")


def _validate_compose(name, raw):
    raw_compose = raw.get("compose") or {}
    if not isinstance(raw_compose, dict):
        raise GatewayError("config_error", f"app {name}: compose must be an object")
    file = raw_compose.get("file", COMPOSE_FILE_DEFAULT)
    if file is None:
        file = COMPOSE_FILE_DEFAULT
    if not isinstance(file, str) or not file or file.startswith("/") or \
            any(part == ".." for part in file.split("/")):
        raise GatewayError("config_error",
                           f"app {name}: compose.file must be a relative path without ..")
    project = raw_compose.get("project") or name
    if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
        raise GatewayError("config_error",
                           f"app {name}: compose.project must match {PROJECT_RE.pattern}")
    return {"file": file, "project": project}


def _validate_app(name, raw):
    if not APP_RE.fullmatch(name):
        raise GatewayError("config_error", f"invalid app id {name!r}")
    if not isinstance(raw, dict):
        raise GatewayError("config_error", f"app {name}: must be an object")
    root = raw.get("root")
    repo = raw.get("repo")
    if not isinstance(root, str) or not root.startswith("/"):
        raise GatewayError("config_error", f"app {name}: root must be an absolute path")
    if not isinstance(repo, str) or not repo or repo.startswith("-"):
        raise GatewayError("config_error", f"app {name}: repo must be a non-empty path or URL")
    kind = raw.get("kind") or KIND_DEFAULT
    if not isinstance(kind, str) or kind not in KINDS:
        raise GatewayError("config_error", f"app {name}: kind must be one of: " + ", ".join(KINDS))
    unit = raw.get("unit")
    if kind == "service":
        if not isinstance(unit, str) or not UNIT_RE.fullmatch(unit):
            raise GatewayError("config_error", f"app {name}: unit is not a valid unit name")
    elif kind == "static":
        if unit is not None and (not isinstance(unit, str) or not UNIT_RE.fullmatch(unit)):
            raise GatewayError("config_error", f"app {name}: unit is not a valid unit name")
        unit = unit or None
    else:  # compose: unit is ignored
        unit = None
    build = _validate_build(name, raw.get("build"))
    ssh_key = raw.get("sshKey")
    known_hosts = raw.get("knownHosts")
    if (ssh_key is None) != (known_hosts is None):
        raise GatewayError("config_error", f"app {name}: sshKey and knownHosts must be set together")
    for label, value in (("sshKey", ssh_key), ("knownHosts", known_hosts)):
        if value is None:
            continue
        if not isinstance(value, str) or not value.startswith("/"):
            raise GatewayError("config_error", f"app {name}: {label} must be an absolute path")
        if not _path_inside(root, value):
            raise GatewayError("config_error", f"app {name}: {label} must be inside root {root}")
    compose = _validate_compose(name, raw) if kind == "compose" else None
    mode = raw.get("mode") or "system"
    if mode not in ("system", "user"):
        raise GatewayError("config_error", f"app {name}: mode must be system or user")
    env = raw.get("env") or {}
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and ENV_NAME_RE.fullmatch(key) and isinstance(value, str)
        for key, value in env.items()
    ):
        raise GatewayError("config_error", f"app {name}: env must map valid names to strings")
    try:
        keep = int(raw.get("keep", KEEP_DEFAULT))
    except (TypeError, ValueError):
        raise GatewayError("config_error", f"app {name}: keep must be an integer")
    if not 1 <= keep <= 50:
        raise GatewayError("config_error", f"app {name}: keep must be between 1 and 50")
    try:
        build_timeout = float(raw.get("buildTimeout", BUILD_TIMEOUT_DEFAULT))
    except (TypeError, ValueError):
        raise GatewayError("config_error", f"app {name}: buildTimeout must be a number")
    if not 1 <= build_timeout <= 3600:
        raise GatewayError("config_error", f"app {name}: buildTimeout must be 1..3600 seconds")
    return {
        "app": name,
        "kind": kind,
        "root": root,
        "repo": repo,
        "unit": unit,
        "build": build,
        "health": _validate_health(name, raw.get("health")),
        "aiDeploy": bool(raw.get("aiDeploy", False)),
        "keep": keep,
        "env": dict(env),
        "mode": mode,
        "buildTimeout": build_timeout,
        "sshKey": ssh_key,
        "knownHosts": known_hosts,
        "compose": compose,
    }


def load_apps():
    path = config_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise GatewayError("config_error", f"{path} is missing (run ai-deploy-target bootstrap on the target)")
    except OSError as exc:
        raise GatewayError("config_error", f"cannot read {path}: {type(exc).__name__}: {exc}")
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise GatewayError("config_error", f"{path} is not valid JSON: {exc}")
    if not isinstance(document, dict):
        raise GatewayError("config_error", f"{path} must contain a JSON object")
    raw_apps = document.get("apps") if isinstance(document.get("apps"), dict) else None
    if raw_apps is None:
        raw_apps = {
            key: value
            for key, value in document.items()
            if not key.startswith("_") and key not in ("schema", "version")
        }
    apps = {}
    for name, raw in raw_apps.items():
        apps[name] = _validate_app(name, raw)
    return apps


# --------------------------------------------------------------------------
# per-app state


class AppPaths:
    def __init__(self, cfg):
        self.cfg = cfg
        self.root = Path(cfg["root"])
        self.mirror = self.root / "mirror.git"
        self.releases = self.root / "releases"
        self.current = self.root / "current"
        self.history = self.root / "history.jsonl"
        self.lock = self.root / "deploy.lock"

    def ensure_root(self):
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            self.releases.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise GatewayError("io_error", f"cannot create {self.root}: {type(exc).__name__}: {exc}")


class AppLock:
    def __init__(self, path):
        self.path = path
        self.handle = None

    def __enter__(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.handle = open(self.path, "a+", encoding="utf-8")
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise GatewayError("busy", "another deploy/rollback is running for this app")
        except OSError as exc:
            raise GatewayError("io_error", f"cannot lock {self.path}: {type(exc).__name__}: {exc}")
        return self

    def __exit__(self, *_exc):
        if self.handle is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self.handle.close()
            self.handle = None
        return False


def release_sha(paths, name):
    meta = paths.releases / name / ".ai-deploy-release.json"
    try:
        document = json.loads(meta.read_text(encoding="utf-8"))
        sha = document.get("sha")
        if isinstance(sha, str) and SHA_RE.fullmatch(sha):
            return sha
    except (OSError, ValueError):
        pass
    match = re.search(r"-([0-9a-f]{7})(?:-[0-9]+)?$", name)
    return match.group(1) if match else None


def current_release(paths):
    """(release name, sha) for the current symlink, or (None, None)."""
    if not paths.current.is_symlink():
        return None, None
    try:
        target = os.readlink(paths.current)
    except OSError:
        return None, None
    name = Path(target).name
    if not RELEASE_RE.fullmatch(name) or not (paths.releases / name).is_dir():
        return None, None
    return name, release_sha(paths, name)


def switch_current(paths, name):
    tmp = paths.releases / f".current.tmp.{os.getpid()}"
    try:
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(f"releases/{name}", tmp)
        os.replace(tmp, paths.current)
    except OSError as exc:
        try:
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise GatewayError("io_error", f"cannot switch current to {name}: {type(exc).__name__}: {exc}")


def remove_current(paths):
    try:
        if paths.current.is_symlink():
            paths.current.unlink()
    except OSError:
        pass


def list_releases(paths):
    """Release names newest first. Within one timestamp second the directory mtime decides."""
    try:
        entries = [
            (entry.stat().st_mtime_ns, entry.name)
            for entry in paths.releases.iterdir()
            if entry.is_dir() and RELEASE_RE.fullmatch(entry.name)
        ]
    except OSError:
        return []
    entries.sort(reverse=True)
    return [name for _mtime, name in entries]


def is_healthy_history_entry(entry):
    """True when a history entry records a release that actually ran healthy."""
    return (
        entry.get("op") == "deploy" and entry.get("result") == "deployed"
    ) or (
        entry.get("op") == "rollback" and entry.get("result") == "rolled_back"
    )


def previous_release(paths, current_name):
    """Most recent other kept release that was successfully deployed, else newest other."""
    for entry in reversed(history_read(paths)):
        name = entry.get("release")
        if not isinstance(name, str) or name == current_name:
            continue
        if not (paths.releases / name).is_dir():
            continue
        if is_healthy_history_entry(entry):
            return name
    for name in list_releases(paths):
        if name != current_name:
            return name
    return None


def release_for_sha(paths, sha):
    for name in list_releases(paths):
        if release_sha(paths, name) == sha:
            return name
    return None


def prune_releases(paths, keep, current_name, previous_name):
    names = list_releases(paths)
    protected = {name for name in (current_name, previous_name) if name}
    kept = []
    for name in names:
        if len(kept) < keep or name in protected:
            kept.append(name)
    removed = []
    for name in names:
        if name in kept:
            continue
        shutil.rmtree(paths.releases / name, ignore_errors=True)
        removed.append(name)
    try:
        for entry in paths.releases.iterdir():
            if entry.name.startswith(".current.tmp."):
                entry.unlink(missing_ok=True)
    except OSError:
        pass
    return removed


# --------------------------------------------------------------------------
# history (bounded 500 entries / 1 MiB, atomic rewrite)


def history_read(paths, limit=None):
    try:
        data = paths.history.read_bytes()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    data = data[-HISTORY_READ_CAP:]
    entries = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    if limit is not None:
        entries = entries[-limit:]
    return entries


def history_append(paths, entry):
    entry = dict(entry)
    entry.setdefault("t", utc_now())
    if isinstance(entry.get("detail"), str):
        entry["detail"] = redact(entry["detail"])[:DETAIL_CAP]
    lines = [json.dumps(item, ensure_ascii=False) for item in history_read(paths)]
    lines.append(json.dumps(entry, ensure_ascii=False))
    while len(lines) > HISTORY_MAX_ENTRIES:
        lines.pop(0)
    while len(lines) > 1 and len(("\n".join(lines) + "\n").encode("utf-8")) > HISTORY_MAX_BYTES:
        lines.pop(0)
    tmp = paths.history.with_name(f"{paths.history.name}.tmp.{os.getpid()}")
    try:
        paths.root.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, paths.history)
    except OSError as exc:
        raise GatewayError("io_error", f"cannot write history: {type(exc).__name__}: {exc}")
    finally:
        try:
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    return entry


# --------------------------------------------------------------------------
# git / build / restart / health


def git_bin():
    return os.environ.get("AI_DEPLOY_GIT") or "git"


def git_ssh_command(cfg):
    """Fixed GIT_SSH_COMMAND for a per-app deploy key, or None without one."""
    key = cfg.get("sshKey")
    known_hosts = cfg.get("knownHosts")
    if not key or not known_hosts:
        return None
    argv = [
        "ssh", "-F", "/dev/null", "-i", key, "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
    ]
    return " ".join(shlex.quote(part) for part in argv)


def git_env(cfg, paths):
    env = {
        "PATH": DEFAULT_PATH,
        "HOME": str(paths.root),
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    ssh_command = git_ssh_command(cfg)
    if ssh_command:
        env["GIT_SSH_COMMAND"] = ssh_command
    return env


def build_env(cfg, paths):
    env = {
        "PATH": DEFAULT_PATH,
        "HOME": os.environ.get("HOME") or str(paths.root),
        "LANG": os.environ.get("LANG") or "C.UTF-8",
    }
    env.update(cfg.get("env") or {})
    return env


def ensure_mirror(cfg, paths, steps):
    env = git_env(cfg, paths)
    git = git_bin()
    if paths.mirror.exists():
        if not (paths.mirror / "HEAD").exists():
            raise GatewayError("mirror_invalid", f"{paths.mirror} exists but is not a bare git mirror")
        result = run_capped(
            [git, f"--git-dir={paths.mirror}", "remote", "update", "--prune"],
            timeout=FETCH_TIMEOUT, env=env, cap=16384, tail=True,
        )
        if not result.ok:
            raise GatewayError("fetch_failed", f"git fetch: {result.detail()}")
        steps.append({"step": "fetch", "ok": True, "detail": f"updated {paths.mirror}"})
        return
    result = run_capped(
        [git, "clone", "--mirror", "--no-hardlinks", cfg["repo"], str(paths.mirror)],
        timeout=FETCH_TIMEOUT, env=env, cap=16384, tail=True,
    )
    if not result.ok:
        raise GatewayError("fetch_failed", f"git clone --mirror: {result.detail()}")
    steps.append({"step": "fetch", "ok": True, "detail": f"cloned mirror from {cfg['repo']}"})


def verify_commit(cfg, paths, sha):
    result = run_capped(
        [git_bin(), f"--git-dir={paths.mirror}", "cat-file", "-e", f"{sha}^{{commit}}"],
        timeout=60, env=git_env(cfg, paths), cap=4096,
    )
    if not result.ok:
        raise GatewayError("unknown_sha", f"{sha} is not a commit in the target mirror")


def make_release(cfg, paths, sha):
    paths.releases.mkdir(parents=True, exist_ok=True)
    base = f"{iso_stamp()}-{sha[:7]}"
    name = base
    counter = 2
    while (paths.releases / name).exists():
        name = f"{base}-{counter}"
        counter += 1
    release = paths.releases / name
    try:
        release.mkdir(mode=0o755)
    except OSError as exc:
        raise GatewayError("io_error", f"cannot create release: {type(exc).__name__}: {exc}")
    result = extract_archive(paths.mirror, sha, release, git_env(cfg, paths))
    if not result.ok:
        shutil.rmtree(release, ignore_errors=True)
        raise GatewayError("extract_failed", f"cannot export {sha}: {result.detail()}")
    meta = {"sha": sha, "t": utc_now(), "app": paths.cfg["app"]}
    try:
        (release / ".ai-deploy-release.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    except OSError:
        pass
    return name, release


def run_build(cfg, paths, release, steps):
    build = cfg["build"]
    if not build:
        steps.append({"step": "build", "ok": True, "detail": "no build configured"})
        return
    total = len(build)
    deadline = time.monotonic() + cfg["buildTimeout"]
    for index, argv in enumerate(build, 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GatewayError("build_failed",
                               f"build step {index}/{total} skipped: buildTimeout exhausted")
        result = run_capped(
            argv, timeout=remaining, cwd=release, env=build_env(cfg, paths),
            cap=BUILD_OUTPUT_CAP, tail=True,
        )
        if not result.ok:
            raise GatewayError("build_failed",
                               f"build step {index}/{total} failed: {result.detail()}")
        steps.append({"step": "build", "ok": True,
                      "detail": f"step {index}/{total}: {argv[0]} ok"})
    steps.append({"step": "build", "ok": True, "detail": f"{total} build step(s) ok"})


def relabel_release(release, steps, phase):
    """SELinux restorecon best effort; a failure is recorded but never fatal."""
    if os.environ.get("AI_DEPLOY_SELINUX_FORCE") != "1" and not Path(SELINUX_ENFORCE).exists():
        return
    command = os.environ.get("AI_DEPLOY_RESTORECON") or RESTORECON_DEFAULT
    if not (os.path.isfile(command) and os.access(command, os.X_OK)):
        return
    result = run_capped([command, "-R", "-F", str(release)], timeout=RELABEL_TIMEOUT,
                        cap=8192, tail=True)
    detail = f"after {phase}: {result.detail() or 'restorecon ok'}"
    steps.append({"step": "relabel", "ok": result.ok, "detail": detail})


def restart_app(cfg):
    """Restart the app for its kind; returns (ok, detail, skipped)."""
    kind = cfg.get("kind") or KIND_DEFAULT
    if kind == "static":
        return True, "restart skipped (static app has no unit)", True
    if kind == "compose":
        sudo = os.environ.get("AI_DEPLOY_SUDO") or "sudo"
        compose_up = os.environ.get("AI_DEPLOY_COMPOSE_UP") or COMPOSE_UP_DEFAULT
        argv = [sudo, "-n", compose_up, cfg["app"]]
        result = run_capped(argv, timeout=COMPOSE_RESTART_TIMEOUT, cap=8192, tail=True)
        if not result.ok:
            return False, f"compose up {cfg['app']}: {result.detail()}", False
        return True, f"compose up {cfg['app']} ok", False
    systemctl = os.environ.get("AI_DEPLOY_SYSTEMCTL") or "/usr/bin/systemctl"
    if cfg.get("mode") == "user":
        argv = [systemctl, "--user", "restart", cfg["unit"]]
    else:
        sudo = os.environ.get("AI_DEPLOY_SUDO") or "sudo"
        argv = [sudo, "-n", systemctl, "restart", cfg["unit"]]
    result = run_capped(argv, timeout=RESTART_TIMEOUT, cap=8192, tail=True)
    if not result.ok:
        return False, f"restart {cfg['unit']}: {result.detail()}", False
    return True, f"restarted {cfg['unit']}", False


def restart_step(cfg, name="restart"):
    """Run restart_app and build its recorded step (marking skipped ones)."""
    ok, detail, skipped = restart_app(cfg)
    step = {"step": name, "ok": ok, "detail": detail}
    if skipped:
        step["skipped"] = True
    return ok, detail, step


def health_once(cfg, release_dir, timeout_override=None):
    health = cfg.get("health")
    if not health:
        return {"ok": True, "type": "none", "detail": "no health check configured"}
    if health["type"] == "http":
        timeout = float(health.get("timeout", 5))
        if timeout_override is not None:
            timeout = min(timeout, timeout_override)
        try:
            request = urllib.request.Request(
                health["url"], headers={"User-Agent": f"{PROG}/{VERSION}", "Accept": "*/*"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                code = response.status
                response.read(4096)
            ok = 200 <= code < 300
            return {"ok": ok, "type": "http", "detail": f"HTTP {code}", "code": code}
        except urllib.error.HTTPError as exc:
            return {"ok": False, "type": "http", "detail": f"HTTP {exc.code}", "code": exc.code}
        except Exception as exc:  # noqa: BLE001 - health must never crash the gateway
            return {"ok": False, "type": "http", "detail": f"{type(exc).__name__}: {exc}"}
    if health["type"] == "command":
        timeout = float(health.get("timeout", 5))
        if timeout_override is not None:
            timeout = min(timeout, timeout_override)
        result = run_capped(
            health["argv"], timeout=timeout, cwd=release_dir, env=build_env(cfg, AppPaths(cfg)),
            cap=4096, tail=True,
        )
        return {"ok": result.ok, "type": "command", "detail": result.detail(1000) or "exit 0"}
    return {"ok": False, "type": health["type"], "detail": "unsupported health type"}


def health_check(cfg, release_dir, single=False, timeout_override=None):
    health = cfg.get("health")
    if not health or single:
        return health_once(cfg, release_dir, timeout_override=timeout_override)
    total = float(health.get("totalSeconds", HEALTH_TOTAL_DEFAULT))
    interval = max(float(health.get("interval", HEALTH_INTERVAL_DEFAULT)), 0.01)
    deadline = time.monotonic() + max(total, 0.0)
    result = health_once(cfg, release_dir)
    while not result["ok"]:
        if time.monotonic() + interval > deadline:
            return result
        time.sleep(interval)
        result = health_once(cfg, release_dir)
    return result


# --------------------------------------------------------------------------
# operations


def op_status(_request, apps):
    items = []
    # Bound the whole status answer: health checks get at most STATUS_BUDGET seconds in total.
    deadline = time.monotonic() + STATUS_BUDGET
    for name in sorted(apps):
        cfg = apps[name]
        paths = AppPaths(cfg)
        current_name, current_sha = current_release(paths)
        if current_name:
            remaining = deadline - time.monotonic()
            if remaining <= 0.1:
                health = {"ok": None, "type": (cfg.get("health") or {}).get("type", "none"),
                          "detail": "health check skipped (status budget)"}
            else:
                health = health_check(cfg, paths.releases / current_name, single=True,
                                      timeout_override=min(HEALTH_STATUS_TIMEOUT, remaining))
        else:
            health = {"ok": None, "type": (cfg.get("health") or {}).get("type", "none"),
                      "detail": "no release"}
        last = None
        for entry in reversed(history_read(paths)):
            if entry.get("app") == name:
                last = entry
                break
        if last is not None:
            last = {key: last.get(key) for key in ("t", "op", "sha", "result", "release")}
        items.append({
            "app": name,
            "kind": cfg["kind"],
            "unit": cfg["unit"],
            "mode": cfg["mode"],
            "aiDeploy": cfg["aiDeploy"],
            "current_sha": current_sha,
            "release": current_name,
            "releases": len(list_releases(paths)),
            "health": health,
            "last_deploy": last,
        })
    return {"ok": True, "apps": items}


def op_health(request, apps):
    app = request["app"]
    cfg = apps[app]
    paths = AppPaths(cfg)
    current_name, current_sha = current_release(paths)
    if not current_name:
        return {"ok": False, "error": "no_release", "detail": f"app {app} has no current release",
                "app": app, "current_sha": None}
    result = health_check(cfg, paths.releases / current_name)
    return {
        "ok": bool(result["ok"]),
        "app": app,
        "current_sha": current_sha,
        "result": "healthy" if result["ok"] else "unhealthy",
        "health": result,
    }


def op_logs(request, apps):
    app = request["app"]
    cfg = apps[app]
    if not cfg.get("unit"):
        return {"ok": False, "error": "no_unit", "detail": f"app {app} has no unit", "app": app}
    lines = request.get("lines")
    lines = 50 if lines is None else lines
    since = request.get("since")
    journalctl = os.environ.get("AI_DEPLOY_JOURNALCTL") or "journalctl"
    argv = [journalctl]
    if cfg["mode"] == "user":
        argv.append("--user")
    argv += ["-u", cfg["unit"], "-n", str(lines), "--no-pager", "-o", "short-iso"]
    if since:
        argv += ["--since", since]
    result = run_capped(argv, timeout=30, cap=LOGS_CAP, tail=False)
    if result.error:
        return {"ok": False, "error": "logs_failed", "detail": result.error, "app": app}
    if result.rc != 0:
        return {"ok": False, "error": "logs_failed", "detail": result.detail(),
                "app": app, "unit": cfg["unit"]}
    text = redact(result.out)
    return {
        "ok": True,
        "app": app,
        "unit": cfg["unit"],
        "lines": lines,
        "since": since,
        "truncated": result.out_bytes > result.out_kept,
        "bytes": len(text.encode("utf-8")),
        "output": text,
    }


def op_history(request, apps):
    app = request.get("app")
    if app is not None:
        cfg = apps[app]
        paths = AppPaths(cfg)
        entries = history_read(paths, limit=HISTORY_MAX_ENTRIES)
        bounded = []
        size = 0
        for entry in reversed(entries):
            line = json.dumps(entry, ensure_ascii=False)
            if size + len(line) > RESPONSE_CAP // 2 and bounded:
                break
            bounded.append(entry)
            size += len(line)
        bounded.reverse()
        return {"ok": True, "app": app, "entries": bounded}
    result = []
    for name in sorted(apps):
        paths = AppPaths(apps[name])
        result.append({"app": name, "entries": history_read(paths, limit=HISTORY_ALL_APPS_LIMIT)})
    return {"ok": True, "apps": result}


def op_deploy(request, apps):
    app = request["app"]
    cfg = apps[app]
    if request.get("ai") and not cfg["aiDeploy"]:
        raise GatewayError("policy_denied", f"app {app} is not marked aiDeploy on this target")
    sha = request.get("sha") or ""
    if not SHA_RE.fullmatch(sha):
        raise GatewayError("invalid_sha", "deploy requires a full 40-hex commit SHA")
    paths = AppPaths(cfg)
    paths.ensure_root()
    with AppLock(paths.lock):
        steps = []
        ensure_mirror(cfg, paths, steps)
        verify_commit(cfg, paths, sha)
        previous_name, previous_sha = current_release(paths)
        try:
            name, release = make_release(cfg, paths, sha)
        except GatewayError as exc:
            history_append(paths, {"op": "deploy", "app": app, "sha": sha,
                                   "previous_sha": previous_sha, "result": exc.code,
                                   "detail": exc.detail})
            raise
        steps.append({"step": "export", "ok": True, "detail": f"releases/{name}"})
        relabel_release(release, steps, "extract")
        try:
            run_build(cfg, paths, release, steps)
        except GatewayError as exc:
            shutil.rmtree(release, ignore_errors=True)
            history_append(paths, {"op": "deploy", "app": app, "sha": sha,
                                   "previous_sha": previous_sha, "release": name,
                                   "result": "build_failed", "detail": exc.detail})
            return {"ok": False, "result": "build_failed", "error": exc.code, "app": app,
                    "sha": sha, "previous_sha": previous_sha, "release": name,
                    "detail": exc.detail, "steps": steps}
        relabel_release(release, steps, "build")
        switch_current(paths, name)
        ok, detail, step = restart_step(cfg)
        steps.append(step)
        if not ok:
            if previous_name:
                switch_current(paths, previous_name)
            else:
                remove_current(paths)
            history_append(paths, {"op": "deploy", "app": app, "sha": sha,
                                   "previous_sha": previous_sha, "release": name,
                                   "result": "restart_failed", "detail": detail})
            return {"ok": False, "result": "restart_failed", "error": "restart_failed", "app": app,
                    "sha": sha, "previous_sha": previous_sha, "release": name,
                    "detail": detail, "steps": steps}
        health = health_check(cfg, release)
        steps.append({"step": "health", "ok": bool(health["ok"]), "detail": health["detail"]})
        if not health["ok"]:
            return _deploy_unhealthy(cfg, paths, app, sha, name, previous_name, previous_sha,
                                     health, steps)
        removed = prune_releases(paths, cfg["keep"], name, previous_name)
        history_append(paths, {"op": "deploy", "app": app, "sha": sha, "previous_sha": previous_sha,
                               "release": name, "result": "deployed",
                               "detail": f"health: {health['detail']}"})
        return {"ok": True, "result": "deployed", "app": app, "sha": sha,
                "previous_sha": previous_sha, "release": name, "health": health,
                "pruned": removed, "steps": steps}


def _deploy_unhealthy(cfg, paths, app, sha, name, previous_name, previous_sha, health, steps):
    """Health failed after the switch: restore the previous release and report honestly."""
    if not previous_name:
        remove_current(paths)
        history_append(paths, {"op": "deploy", "app": app, "sha": sha, "previous_sha": None,
                               "release": name, "result": "health_failed",
                               "detail": f"no previous release; health: {health['detail']}"})
        return {"ok": False, "result": "health_failed", "error": "health_failed", "app": app,
                "sha": sha, "previous_sha": None, "release": name, "health": health,
                "detail": f"health check failed and there is no previous release to roll back to: "
                          f"{health['detail']}", "steps": steps}
    switch_current(paths, previous_name)
    restart_ok, restart_detail, step = restart_step(cfg, "rollback-restart")
    steps.append(step)
    restored_health = None
    if restart_ok:
        restored_health = health_check(cfg, paths.releases / previous_name)
        steps.append({"step": "rollback-health", "ok": bool(restored_health["ok"]),
                      "detail": restored_health["detail"]})
    if restart_ok and restored_health and restored_health["ok"]:
        history_append(paths, {"op": "deploy", "app": app, "sha": sha,
                               "previous_sha": previous_sha, "release": name,
                               "result": "rolled_back",
                               "detail": f"health: {health['detail']}"})
        return {"ok": False, "result": "rolled_back", "error": "health_failed", "app": app,
                "sha": sha, "previous_sha": previous_sha, "release": name, "health": health,
                "restored_release": previous_name, "restored_health": restored_health,
                "detail": f"health check failed ({health['detail']}); restored "
                          f"{previous_name}", "steps": steps}
    history_append(paths, {"op": "deploy", "app": app, "sha": sha, "previous_sha": previous_sha,
                           "release": name, "result": "error",
                           "detail": f"health: {health['detail']}; restore restart={restart_detail}"})
    return {"ok": False, "result": "error", "error": "rollback_unhealthy", "app": app,
            "sha": sha, "previous_sha": previous_sha, "release": name, "health": health,
            "restored_release": previous_name, "restored_health": restored_health,
            "detail": "health check failed and the previous release did not come back healthy; "
                      "human inspection required", "steps": steps}


def op_restart(request, apps):
    app = request["app"]
    cfg = apps[app]
    if request.get("ai"):
        raise GatewayError("policy_denied", "restart is not an AI-allowed operation")
    ok, detail, _skipped = restart_app(cfg)
    return {"ok": ok, "app": app, "result": "restarted" if ok else "restart_failed",
            "detail": detail}


def op_rollback(request, apps):
    app = request["app"]
    cfg = apps[app]
    if request.get("ai"):
        raise GatewayError("policy_denied", "rollback is human-only; the target refuses AI rollback")
    paths = AppPaths(cfg)
    paths.ensure_root()
    with AppLock(paths.lock):
        current_name, current_sha = current_release(paths)
        to = request.get("to")
        if to is not None:
            if not SHA_RE.fullmatch(to):
                raise GatewayError("invalid_sha", "rollback --to requires a full 40-hex commit SHA")
            target = release_for_sha(paths, to)
            if target is None:
                raise GatewayError("unknown_release", f"{to} is not among the kept releases")
        else:
            target = previous_release(paths, current_name)
            if target is None:
                raise GatewayError("no_previous_release",
                                   "no other kept release is available to roll back to")
        if target == current_name:
            raise GatewayError("already_current", f"{target} is already the current release")
        target_sha = release_sha(paths, target)
        steps = [{"step": "target", "ok": True, "detail": f"releases/{target}"}]
        switch_current(paths, target)
        ok, detail, step = restart_step(cfg)
        steps.append(step)
        if not ok:
            if current_name:
                switch_current(paths, current_name)
            else:
                remove_current(paths)
            history_append(paths, {"op": "rollback", "app": app, "sha": target_sha,
                                   "previous_sha": current_sha, "release": target,
                                   "result": "error", "detail": detail})
            return {"ok": False, "result": "error", "error": "restart_failed", "app": app,
                    "sha": target_sha, "previous_sha": current_sha, "release": target,
                    "detail": detail, "steps": steps}
        health = health_check(cfg, paths.releases / target)
        steps.append({"step": "health", "ok": bool(health["ok"]), "detail": health["detail"]})
        if not health["ok"]:
            if current_name:
                switch_current(paths, current_name)
                restart_ok, restart_detail, step = restart_step(cfg, "restore-restart")
                steps.append(step)
            else:
                remove_current(paths)
            history_append(paths, {"op": "rollback", "app": app, "sha": target_sha,
                                   "previous_sha": current_sha, "release": target,
                                   "result": "error",
                                   "detail": f"health: {health['detail']}"})
            return {"ok": False, "result": "error", "error": "rollback_unhealthy", "app": app,
                    "sha": target_sha, "previous_sha": current_sha, "release": target,
                    "health": health, "detail": "rollback target did not come back healthy; "
                                                "human inspection required", "steps": steps}
        history_append(paths, {"op": "rollback", "app": app, "sha": target_sha,
                               "previous_sha": current_sha, "release": target,
                               "result": "rolled_back", "detail": f"health: {health['detail']}"})
        return {"ok": True, "result": "rolled_back", "app": app, "sha": target_sha,
                "previous_sha": current_sha, "release": target, "health": health, "steps": steps}


DISPATCH = {
    "status": op_status,
    "deploy": op_deploy,
    "restart": op_restart,
    "health": op_health,
    "logs": op_logs,
    "rollback": op_rollback,
    "history": op_history,
}


# --------------------------------------------------------------------------
# request / response


def parse_request(raw):
    if len(raw) > REQUEST_CAP:
        raise GatewayError("invalid_request", f"request larger than {REQUEST_CAP} bytes")
    if not raw.strip():
        return {}
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise GatewayError("invalid_request", f"request is not valid JSON: {exc}")
    if not isinstance(request, dict):
        raise GatewayError("invalid_request", "request must be a JSON object")
    unknown = sorted(set(request) - set(REQUEST_FIELDS))
    if unknown:
        raise GatewayError("invalid_request", f"unknown request fields: {', '.join(unknown)}")
    app = request.get("app")
    if app is not None and (not isinstance(app, str) or not APP_RE.fullmatch(app)):
        raise GatewayError("invalid_request", "app must be a valid app id")
    sha = request.get("sha")
    if sha is not None and not isinstance(sha, str):
        raise GatewayError("invalid_request", "sha must be a string")
    to = request.get("to")
    if to is not None and not isinstance(to, str):
        raise GatewayError("invalid_request", "to must be a string")
    ai = request.get("ai")
    if ai is not None and not isinstance(ai, bool):
        raise GatewayError("invalid_request", "ai must be a boolean")
    lines = request.get("lines")
    if lines is not None and (isinstance(lines, bool) or not isinstance(lines, int)):
        raise GatewayError("invalid_request", "lines must be an integer")
    if lines is not None and not 1 <= lines <= 500:
        raise GatewayError("invalid_request", "lines must be between 1 and 500")
    since = request.get("since")
    if since is not None:
        if not isinstance(since, str) or len(since) > 40 or not SINCE_RE.fullmatch(since):
            raise GatewayError("invalid_request", "since must be like 1h, 30m, 2d or an ISO timestamp")
    return request


def require_app(request, apps, op):
    app = request.get("app")
    if not app:
        raise GatewayError("invalid_request", f"{op} requires an app")
    if app not in apps:
        raise GatewayError("unknown_app", f"app {app} is not in the target allowlist")
    return app


def dispatch(op, request, apps):
    if op in ("deploy", "restart", "health", "logs", "rollback"):
        require_app(request, apps, op)
    return DISPATCH[op](request, apps)


def emit(payload, exit_code):
    payload = dict(payload)
    payload.setdefault("schema", SCHEMA)
    payload.setdefault("ok", False)
    payload["gateway"] = VERSION
    try:
        data = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        data = json.dumps({"schema": SCHEMA, "ok": False, "error": "internal_error",
                           "detail": "response could not be serialized"})
    if len(data.encode("utf-8")) > RESPONSE_CAP:
        data = json.dumps({"schema": SCHEMA, "ok": False, "error": "response_too_large",
                           "detail": f"response exceeded {RESPONSE_CAP} bytes"})
    try:
        sys.stdout.write(data + "\n")
        sys.stdout.flush()
    except (BrokenPipeError, OSError):
        pass
    return exit_code


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--version"]:
        print(f"{PROG} {VERSION}")
        return 0
    op = (os.environ.get("SSH_ORIGINAL_COMMAND") or "").strip()
    if op not in OPS:
        return emit({"op": None, "error": "invalid_op",
                     "detail": "SSH_ORIGINAL_COMMAND must be exactly one of: " + " ".join(OPS)}, 1)
    try:
        raw = sys.stdin.buffer.read(REQUEST_CAP + 1)
        request = parse_request(raw)
        apps = load_apps()
        response = dispatch(op, request, apps)
    except GatewayError as exc:
        return emit({"op": op, "error": exc.code, "detail": exc.detail}, 1)
    except KeyboardInterrupt:
        return emit({"op": op, "error": "interrupted", "detail": "interrupted"}, 130)
    except Exception as exc:  # noqa: BLE001 - the gateway must always answer JSON
        return emit({"op": op, "error": "internal_error",
                     "detail": redact(f"{type(exc).__name__}: {exc}")[:DETAIL_CAP]}, 1)
    response = dict(response)
    response.setdefault("op", op)
    return emit(response, 0 if response.get("ok") else 1)


if __name__ == "__main__":
    sys.exit(main())
