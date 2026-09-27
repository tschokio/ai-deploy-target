#!/usr/bin/env python3
"""ai-deploy compose wrapper (trust level root, one app per exact sudoers rule).

Installed on the target as /usr/local/lib/ai-deploy/compose-up and invoked by the
gateway as root through exactly one sudoers rule per compose app:

    ai-deploy ALL=(root) NOPASSWD: /usr/local/lib/ai-deploy/compose-up <app>

The caller passes exactly one app name. The wrapper never trusts anything else the
caller says: it re-reads the target-owned allowlist /etc/ai-deploy/apps.json,
requires ``kind: compose``, resolves ``<root>/current`` with realpath and requires
it to live inside ``<root>/releases/``, and requires the compose file to resolve
inside the current release. Then it runs

    docker compose -p <project> -f <file> [--env-file <app>.env] up -d --build --remove-orphans

with cwd=<current release>, a minimal environment, a 900 s timeout (killed as a
process group) and bounded output (last 16 KiB). It never starts a shell.

Test-only overrides (honored only when AI_DEPLOY_TEST=1):
  AI_DEPLOY_CONFIG            apps.json path       (default /etc/ai-deploy/apps.json)
  AI_DEPLOY_DOCKER            docker path          (default /usr/bin/docker)
  AI_DEPLOY_ENV_FILE          app env file path    (default /etc/ai-deploy/<app>.env)
  AI_DEPLOY_COMPOSE_TIMEOUT   timeout in seconds   (default 900)
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path

PROG = "ai-deploy-compose-up"

APP_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

CONFIG_DEFAULT = "/etc/ai-deploy/apps.json"
ENV_DIR_DEFAULT = "/etc/ai-deploy"
DOCKER_DEFAULT = "/usr/bin/docker"
COMPOSE_FILE_DEFAULT = "compose.yml"
TIMEOUT_DEFAULT = 900
OUTPUT_CAP = 16 * 1024
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _package_version():
    """Shared package version: sibling VERSION when installed, else a constant."""
    try:
        text = (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.2.0"
    return text or "0.2.0"


VERSION = _package_version()


def test_mode():
    return os.environ.get("AI_DEPLOY_TEST") == "1"


def usage(message):
    sys.stderr.write(f"{PROG}: {message}\n")
    return 2


def config_path():
    if test_mode() and os.environ.get("AI_DEPLOY_CONFIG"):
        return Path(os.environ["AI_DEPLOY_CONFIG"])
    return Path(CONFIG_DEFAULT)


def docker_path():
    if test_mode() and os.environ.get("AI_DEPLOY_DOCKER"):
        return os.environ["AI_DEPLOY_DOCKER"]
    return DOCKER_DEFAULT


def env_file_for(app):
    if test_mode() and os.environ.get("AI_DEPLOY_ENV_FILE"):
        return Path(os.environ["AI_DEPLOY_ENV_FILE"])
    return Path(ENV_DIR_DEFAULT) / f"{app}.env"


def timeout_seconds():
    if test_mode() and os.environ.get("AI_DEPLOY_COMPOSE_TIMEOUT"):
        try:
            value = float(os.environ["AI_DEPLOY_COMPOSE_TIMEOUT"])
        except ValueError:
            raise ValueError("AI_DEPLOY_COMPOSE_TIMEOUT must be a number")
        if value <= 0:
            raise ValueError("AI_DEPLOY_COMPOSE_TIMEOUT must be positive")
        return value
    return float(TIMEOUT_DEFAULT)


def inside(parent_real, child_real):
    """True when child_real is strictly inside the already resolved parent_real."""
    parent = parent_real.rstrip(os.sep) or os.sep
    if parent == os.sep:
        return child_real.startswith(os.sep) and child_real != os.sep
    return child_real.startswith(parent + os.sep)


def _kill_group(proc):
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError, OSError):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue


def run_docker(argv, cwd, timeout):
    """Run docker with a minimal env, tail-capped output and a killed process group."""
    env = {"PATH": DEFAULT_PATH, "LANG": os.environ.get("LANG") or "C.UTF-8"}
    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        )
    except OSError as exc:
        sys.stderr.write(f"{PROG}: cannot run {argv[0]}: {type(exc).__name__}: {exc}\n")
        return 127
    buffer = bytearray()
    sink = {"total": 0}

    def reader():
        while True:
            try:
                chunk = proc.stdout.read(65536)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            sink["total"] += len(chunk)
            buffer.extend(chunk)
            if len(buffer) > OUTPUT_CAP:
                del buffer[: len(buffer) - OUTPUT_CAP]

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rc = -9
    thread.join(2)
    text = bytes(buffer).decode("utf-8", "replace")
    if text:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    if timed_out:
        sys.stderr.write(f"{PROG}: docker compose timed out after {timeout:g}s\n")
        return 124
    if rc is None:
        return 1
    if rc < 0:
        return 128 + (-rc)
    return rc


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--version"]:
        print(f"{PROG} {VERSION}")
        return 0
    if len(argv) != 1:
        return usage("usage: compose-up <app>")
    app = argv[0]
    if not APP_RE.fullmatch(app):
        return usage(f"invalid app name {app!r}")

    path = config_path()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return usage(f"{path} is missing")
    except (OSError, ValueError) as exc:
        return usage(f"cannot read {path}: {type(exc).__name__}: {exc}")
    if not isinstance(document, dict):
        return usage(f"{path} must contain a JSON object")
    raw_apps = document.get("apps") if isinstance(document.get("apps"), dict) else None
    if raw_apps is None:
        raw_apps = {
            key: value
            for key, value in document.items()
            if not key.startswith("_") and key not in ("schema", "version")
        }
    raw = raw_apps.get(app)
    if not isinstance(raw, dict):
        return usage(f"app {app} is not in {path}")
    if (raw.get("kind") or "service") != "compose":
        return usage(f"app {app} is not marked kind compose")
    root = raw.get("root")
    if not isinstance(root, str) or not root.startswith("/"):
        return usage(f"app {app}: root must be an absolute path")

    compose = raw.get("compose") or {}
    if not isinstance(compose, dict):
        return usage(f"app {app}: compose must be an object")
    file = compose.get("file", COMPOSE_FILE_DEFAULT)
    if file is None:
        file = COMPOSE_FILE_DEFAULT
    project = compose.get("project") or app
    if not isinstance(file, str) or not file or file.startswith("/") or \
            any(part == ".." for part in file.split("/")):
        return usage(f"app {app}: compose.file must be a relative path without ..")
    if not isinstance(project, str) or not PROJECT_RE.fullmatch(project):
        return usage(f"app {app}: compose.project is invalid")

    releases_real = os.path.realpath(os.path.join(root, "releases"))
    current_real = os.path.realpath(os.path.join(root, "current"))
    if not os.path.isdir(current_real) or not inside(releases_real, current_real):
        return usage(f"app {app}: current does not resolve inside {releases_real}/")
    file_real = os.path.realpath(os.path.join(current_real, file))
    if not os.path.isfile(file_real) or not inside(current_real, file_real):
        return usage(f"app {app}: compose file {file!r} does not resolve inside the current release")

    try:
        timeout = timeout_seconds()
    except ValueError as exc:
        return usage(str(exc))

    command = [docker_path(), "compose", "-p", project, "-f", file_real]
    app_env = env_file_for(app)
    if app_env.is_file():
        command += ["--env-file", str(app_env)]
    command += ["up", "-d", "--build", "--remove-orphans"]
    return run_docker(command, current_real, timeout)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
