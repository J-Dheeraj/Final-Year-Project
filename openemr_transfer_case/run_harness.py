"""OpenEMR healthcare transfer case: GHSA-q366-cv5v-83w8, unauthenticated
admin.php information disclosure. Docker-based harness, mirroring the
free5GC full-deployment design: a minimal MariaDB container (only the
two tables admin.php's own read path needs, not OpenEMR's full schema),
a minimal PHP container (php:8.2-cli + mysqli, no Apache, no full
OpenEMR setup wizard) with the real, unmodified OpenEMR checkout
bind-mounted at runtime, and a Python-orchestrated request sequence.

NO_PAID_BACKEND=1 is set defensively even though this script never
calls an LLM backend - the "patch" here is the real upstream
maintainers' own fix commit, checked out directly, not generated.

Requires: Docker Desktop running, the openemr-transfer-php:latest image
already built (docker build -f Dockerfile.php -t openemr-transfer-php:latest .),
and a real clone of github.com/openemr/openemr at
openemr_transfer_case/_work/checkout/ (see SETUP.md).

Run: python openemr_transfer_case/run_harness.py
"""
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["NO_PAID_BACKEND"] = "1"

import requests  # noqa: E402

HERE = Path(__file__).parent.resolve()
CHECKOUT_DIR = HERE / "_work" / "checkout"
NETWORK = "openemr-transfer-net"
DB_CONTAINER = "openemr-transfer-db"
PHP_CONTAINER = "openemr-transfer-php"
DB_ROOT_PASSWORD = "testpass-local-only"
DB_NAME = "openemr_test"
PHP_IMAGE = "openemr-transfer-php:latest"
BASE_URL = "http://127.0.0.1:8090"

FIXED_COMMIT = "50f789fad45ada625fe8d0faf0c7a9c15ef52aa5"
VULN_COMMIT = "b5313ea25f7928538eb793d4b4184ed4601d9afd"

SQLCONF_PHP = f"""<?php
$config = 1;
$host = '{DB_CONTAINER}';
$port = '3306';
$login = 'root';
$pass = '{DB_ROOT_PASSWORD}';
$dbase = '{DB_NAME}';
"""


def run(*args, check=True):
    return subprocess.run(list(args), capture_output=True, text=True, check=check)


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=CHECKOUT_DIR, capture_output=True, text=True, check=check)


def ensure_network():
    existing = run("docker", "network", "ls", "--format", "{{.Name}}").stdout.split()
    if NETWORK not in existing:
        run("docker", "network", "create", NETWORK)


def start_db():
    run("docker", "rm", "-f", DB_CONTAINER, check=False)
    run(
        "docker", "run", "-d", "--name", DB_CONTAINER, "--network", NETWORK,
        "-e", f"MARIADB_ROOT_PASSWORD={DB_ROOT_PASSWORD}",
        "-e", f"MARIADB_DATABASE={DB_NAME}",
        "mariadb:10.11",
    )
    # Wait for MariaDB to accept the real root login before loading the
    # schema. mysqladmin ping alone is not enough: the official image's
    # entrypoint runs an internal, password-less bootstrap instance over
    # the Unix socket before the final, fully-initialized server (with
    # MARIADB_ROOT_PASSWORD actually committed) takes over, so a ping
    # can succeed against the bootstrap instance moments before the real
    # root password exists - retrying the actual authenticated login
    # avoids that race.
    schema_sql = (HERE / "schema.sql").read_text(encoding="utf-8")
    for _ in range(60):
        load = subprocess.run(
            ["docker", "exec", "-i", DB_CONTAINER, "mysql", "-uroot", f"-p{DB_ROOT_PASSWORD}", DB_NAME],
            input=schema_sql, capture_output=True, text=True,
        )
        if load.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"Schema load never succeeded: {load.stderr}")


def stop_db():
    run("docker", "rm", "-f", DB_CONTAINER, check=False)


def checkout_commit(commit: str):
    git("checkout", "--quiet", "--force", commit)
    return git("rev-parse", "HEAD").stdout.strip()


def write_sqlconf():
    site_dir = CHECKOUT_DIR / "sites" / "default"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "sqlconf.php").write_text(SQLCONF_PHP, encoding="utf-8")


def start_php(env_admin_enabled: bool = False):
    run("docker", "rm", "-f", PHP_CONTAINER, check=False)
    cmd = [
        "docker", "run", "-d", "--name", PHP_CONTAINER, "--network", NETWORK,
        "-p", "127.0.0.1:8090:8000",
        "-v", f"{CHECKOUT_DIR}:/var/www/openemr",
    ]
    if env_admin_enabled:
        cmd += ["-e", "OPENEMR_ADMIN_PHP_ENABLED=1"]
    cmd += [PHP_IMAGE]
    run(*cmd)


def stop_php():
    run("docker", "rm", "-f", PHP_CONTAINER, check=False)


def wait_for_php(retries=30, delay=1.0):
    """Waits only for the port to accept TCP connections, not for a full
    HTTP response - admin.php's own request/response behaviour (which
    may legitimately be slow or hang on a bad DB connection) is checked
    separately by request_admin(), with its own explicit timeout, so a
    single slow request here can't make this loop appear to never
    finish."""
    import socket
    for _ in range(retries):
        try:
            with socket.create_connection(("127.0.0.1", 8090), timeout=2):
                return True
        except OSError:
            time.sleep(delay)
    return False


def raw(resp):
    return {"status_code": resp.status_code, "headers": dict(resp.headers), "body": resp.text}


def request_admin():
    """PHP's built-in dev server can accept a TCP connection (satisfying
    wait_for_php's readiness check) fractionally before its request-
    handling loop is actually ready, which resets the very next request
    with a bare connection close; retrying a couple of times absorbs
    that specific startup race without masking a genuine failure."""
    last_error = None
    for attempt in range(5):
        try:
            r = requests.get(f"{BASE_URL}/admin.php", timeout=10)
            return raw(r)
        except requests.exceptions.ConnectionError as exc:
            last_error = exc
            time.sleep(1)
    raise last_error


def main():
    (HERE / "evidence").mkdir(exist_ok=True)
    (HERE / "evidence" / "container_or_process_logs").mkdir(exist_ok=True)

    ensure_network()
    start_db()

    print("Vulnerable commit:", VULN_COMMIT)
    real_vuln_commit = checkout_commit(VULN_COMMIT)
    write_sqlconf()
    start_php(env_admin_enabled=False)
    if not wait_for_php():
        raise RuntimeError("PHP (vulnerable, default) never became reachable on :8090")
    vulnerable_default = request_admin()
    (HERE / "evidence" / "container_or_process_logs" / "vulnerable_php.log").write_text(
        run("docker", "logs", PHP_CONTAINER, check=False).stdout
        + run("docker", "logs", PHP_CONTAINER, check=False).stderr,
        encoding="utf-8",
    )
    stop_php()

    print("Fixed commit:", FIXED_COMMIT)
    real_fixed_commit = checkout_commit(FIXED_COMMIT)
    write_sqlconf()

    start_php(env_admin_enabled=False)
    if not wait_for_php():
        raise RuntimeError("PHP (patched, default) never became reachable on :8090")
    patched_default = request_admin()
    stop_php()

    start_php(env_admin_enabled=True)
    if not wait_for_php():
        raise RuntimeError("PHP (patched, opt-in) never became reachable on :8090")
    patched_optin = request_admin()
    (HERE / "evidence" / "container_or_process_logs" / "patched_php.log").write_text(
        run("docker", "logs", PHP_CONTAINER, check=False).stdout
        + run("docker", "logs", PHP_CONTAINER, check=False).stderr,
        encoding="utf-8",
    )
    stop_php()

    stop_db()

    for label, r in (
        ("vulnerable_default", vulnerable_default),
        ("patched_default", patched_default),
        ("patched_optin", patched_optin),
    ):
        (HERE / "evidence" / f"{label}_response.log").write_text(
            json.dumps(r, indent=2), encoding="utf-8")

    vulnerable_leaked = (
        vulnerable_default["status_code"] == 200
        and "Multi Site Administration" in vulnerable_default["body"]
    )
    patched_default_blocked = (
        patched_default["status_code"] == 403
        and "Multi Site Administration" not in patched_default["body"]
    )
    patched_optin_works = (
        patched_optin["status_code"] == 200
        and "Multi Site Administration" in patched_optin["body"]
    )

    if vulnerable_leaked and patched_default_blocked and patched_optin_works:
        verdict_str = "confirmed_fix"
    elif not patched_default_blocked:
        verdict_str = "not_blocked"
    elif patched_default_blocked and not patched_optin_works:
        verdict_str = "regression_broke_route"
    else:
        verdict_str = "inconclusive_crash"

    manifest = {
        "advisory": "GHSA-q366-cv5v-83w8",
        "component": "OpenEMR admin.php",
        "vulnerable_commit": real_vuln_commit,
        "fixed_commit": real_fixed_commit,
        "deployment": {
            "mariadb": "real, official mariadb:10.11 image, minimal 2-table schema (schema.sql)",
            "php": "real, official php:8.2-cli image + mysqli, real unmodified OpenEMR checkout bind-mounted",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulnerable_default": vulnerable_default,
        "patched_default": patched_default,
        "patched_optin": patched_optin,
    }
    (HERE / "evidence" / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = {
        "advisory": "GHSA-q366-cv5v-83w8",
        "vulnerable_default_leaked_metadata": vulnerable_leaked,
        "patched_default_blocked": patched_default_blocked,
        "patched_optin_still_works": patched_optin_works,
        "verdict": verdict_str,
    }
    (HERE / "evidence" / "verdict.json").write_text(json.dumps(verdict, indent=2), encoding="utf-8")

    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
