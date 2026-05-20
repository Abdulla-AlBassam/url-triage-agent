"""
sandbox_fetch — open a URL in a sealed-off browser and report what it shows.

This is the heavyweight tool. The agent should reach for it only after the
cheaper checks (DNS, WHOIS, threat-intel lookups) have left genuine doubt.

What "sealed-off" means here:
  - A fresh Docker container per fetch (`--rm`-style: no state carries over).
  - No host bind mounts. The container can't see the user's files.
  - Linux capabilities dropped to the bare minimum (`NET_ADMIN` only, so the
    entrypoint can set iptables rules; everything else is denied).
  - `--security-opt=no-new-privileges`: no setuid escalation.
  - `--read-only` root filesystem with a small `/tmp` tmpfs for scratch.
  - 512 MB memory, 1 CPU. A runaway page can't eat the laptop.
  - Outbound traffic locked down to the target host's IPs on 80/443 only.
    A malicious page can't quietly reach out to a C2 server or third-party
    tracker from inside the container.

How we get data out:
  - The container prints a single JSON line to stdout. We parse it.
  - The screenshot lives in the container's tmpfs. We extract it via
    `docker cp` before removing the container.

If Docker isn't running, the tool reports itself unavailable and the agent
works around it — the same pattern every other "needs an API key" tool uses.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from ..tool_registry import register_tool
from ._helpers import to_hostname


IMAGE_NAME = "url-triage-sandbox:latest"
SANDBOX_DIR = Path(__file__).resolve().parents[3] / "sandbox"
SCREENSHOT_DIR = Path("reports") / "screenshots"


def _docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "`docker` CLI not on PATH"
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"docker version check failed: {exc}"
    if result.returncode != 0:
        return False, f"docker daemon not reachable: {result.stderr.strip()[:200]}"
    return True, result.stdout.strip()


def _image_exists() -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", IMAGE_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def _build_image() -> tuple[bool, str]:
    """Build the sandbox image. First call is slow (~1.5 GB pull); cached after."""
    if not SANDBOX_DIR.exists():
        return False, f"sandbox directory missing: {SANDBOX_DIR}"
    proc = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(SANDBOX_DIR)],
        capture_output=True, text=True,
    )
    ok = proc.returncode == 0
    log = (proc.stdout or "") + (proc.stderr or "")
    return ok, log


@register_tool(
    name="sandbox_fetch",
    description=(
        "Render a URL in a sandboxed Chromium browser inside Docker. Returns "
        "the final URL after redirects, page title, visible text, forms (with "
        "action URLs and whether they contain password inputs), network "
        "requests the page made, console logs, and the path to a saved "
        "screenshot. The container has no host access and outbound traffic "
        "is restricted to the target host. Expensive (a few seconds and "
        "non-trivial memory); use only after cheaper tools have left doubt."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The full URL to render. Must include scheme (http/https).",
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "How long to wait for the page to load. Default 20.",
                "default": 20,
            },
        },
        "required": ["url"],
    },
)
def sandbox_fetch(url: str, timeout_seconds: int = 20) -> dict:
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    hostname = parsed.hostname or to_hostname(url)
    if not hostname:
        return {"url": url, "error": "Could not parse hostname from URL"}

    ok, info = _docker_available()
    if not ok:
        return {
            "available": False,
            "reason": info,
            "hint": "Start Docker Desktop, then retry.",
        }

    if not _image_exists():
        built, log = _build_image()
        if not built:
            return {
                "url": url,
                "error": "failed to build sandbox image",
                "build_log_tail": log[-1500:],
            }

    container_name = f"triage-sandbox-{uuid.uuid4().hex[:10]}"
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    screenshot_dst = SCREENSHOT_DIR / f"{container_name}.png"
    strict_egress = os.getenv("STRICT_EGRESS", "1")

    # Capability budget:
    #   - NET_ADMIN: the entrypoint needs it to apply iptables rules.
    #   - SETUID/SETGID: gosu needs them to drop from root to pwuser; gosu
    #     then strips all caps from the child, so the running browser has
    #     none of them.
    # Everything else is dropped.
    # `--rm` removes the container the moment it exits. We're not relying
    # on the container's filesystem after it stops (the screenshot is base64'd
    # into the JSON output), so auto-cleanup is the simplest contract.
    cmd = [
        "docker", "run",
        "--rm",
        "--name", container_name,
        "--cap-drop", "ALL",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "SETUID",
        "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=128m,exec",
        "--tmpfs", "/run:rw,size=8m",
        "--memory", "768m",
        "--cpus", "1",
        "--network", "bridge",
        "-e", f"TARGET_URL={url}",
        "-e", f"TARGET_HOST={hostname}",
        "-e", f"TIMEOUT_MS={timeout_seconds * 1000}",
        "-e", f"STRICT_EGRESS={strict_egress}",
        IMAGE_NAME,
    ]

    started = time.time()
    try:
        # Overall timeout = page timeout + 90s for container startup + chromium boot
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds + 90,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        return {
            "url": url,
            "error": f"sandbox exceeded outer timeout ({timeout_seconds + 90}s)",
        }
    elapsed = round(time.time() - started, 1)

    if proc.returncode != 0:
        return {
            "url": url,
            "error": f"sandbox exited with code {proc.returncode}",
            "stdout_tail": (proc.stdout or "")[-800:],
            "stderr_tail": (proc.stderr or "")[-800:],
            "elapsed_seconds": elapsed,
        }

    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1]) if proc.stdout.strip() else {}
    except (json.JSONDecodeError, IndexError):
        return {
            "url": url,
            "error": "sandbox returned non-JSON output",
            "stdout_tail": (proc.stdout or "")[-800:],
            "stderr_tail": (proc.stderr or "")[-800:],
            "elapsed_seconds": elapsed,
        }

    # Pull the base64 screenshot out of the payload, write it to disk, and
    # replace the field with the filesystem path. The agent never needs to
    # see the raw bytes — that would balloon the context for no benefit.
    screenshot_path: str | None = None
    b64 = data.pop("screenshot_b64", None)
    if b64:
        try:
            png_bytes = base64.b64decode(b64)
            if png_bytes:
                screenshot_dst.write_bytes(png_bytes)
                screenshot_path = str(screenshot_dst)
        except Exception:
            pass
    data["screenshot_path"] = screenshot_path
    data["elapsed_seconds"] = elapsed
    return data
