"""End-to-end harness: launches a scenario app as a real subprocess (real
uvicorn, real TCP port, real HTTP over the wire).

Needs the real jetio package, not the mock tests/conftest.py substitutes
(see tests_integration/README.md for why) -- AND specifically the fixed
local jetio checkout (branch fix/metaclass-api-config-mro-lookup at
../jetio, a sibling checkout), not whatever's on PyPI, since proving
JetioAuthMixin works end-to-end depends on that fix too. JETIO_REPO_PATH
lets this be overridden if that sibling checkout lives somewhere else.
"""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

APPS_DIR = Path(__file__).parent / "apps"
REPO_ROOT = Path(__file__).parent.parent
DEFAULT_JETIO_REPO = REPO_ROOT.parent / "jetio"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_ready(base_url: str, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{base_url}/docs", timeout=1.0)
            if resp.status_code == 200:
                return
        except httpx.TransportError as e:
            last_error = e
        time.sleep(0.2)
    return last_error


def run_scenario_app(tmp_path, script_name: str):
    jetio_repo = Path(os.environ.get("JETIO_REPO_PATH", str(DEFAULT_JETIO_REPO)))
    if not (jetio_repo / "jetio" / "__init__.py").exists():
        pytest.skip(
            f"sibling jetio checkout not found at {jetio_repo} -- set JETIO_REPO_PATH "
            "to a checkout of jetio's fix/metaclass-api-config-mro-lookup branch to run these"
        )

    port = _free_port()
    script = APPS_DIR / script_name
    env = dict(os.environ)
    env["JETIO_APP_PORT"] = str(port)
    env["PYTHONIOENCODING"] = "utf-8"
    # Local jetio_auth (this checkout, with the mixins fix) and the sibling
    # jetio checkout (with the API-config MRO fix) both need to shadow
    # whatever's installed from PyPI in site-packages.
    existing_path = env.get("PYTHONPATH", "")
    parts = [str(REPO_ROOT), str(jetio_repo)]
    if existing_path:
        parts.append(existing_path)
    env["PYTHONPATH"] = os.pathsep.join(parts)

    process = subprocess.Popen(
        [sys.executable, str(script)],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    error = _wait_until_ready(base_url)
    if error is not None and process.poll() is not None:
        out, _ = process.communicate(timeout=5)
        raise RuntimeError(f"scenario app exited before becoming ready (code {process.returncode}):\n{out}")
    return process, base_url


def stop_scenario_app(process) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@pytest.fixture
def auth_app(tmp_path):
    process, base_url = run_scenario_app(tmp_path, "mixin_auth_scenario_app.py")
    yield base_url
    stop_scenario_app(process)
