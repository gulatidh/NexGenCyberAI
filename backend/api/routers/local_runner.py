"""Local Runner Setup — install and configure scanners to run directly on
the local Kali/WSL machine instead of dispatching to GitHub Actions."""

import asyncio, json, os, shutil, socket, stat, subprocess, tarfile, tempfile, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from core.security import get_current_user
from api.models.models import LocalRunnerTool

router = APIRouter(prefix="/local-runner", tags=["local-runner"])

OWLET_BIN = Path.home() / ".owlet" / "bin"

# ── OS detection ──────────────────────────────────────────────────────────────

def _is_kali() -> bool:
    try:
        return "kali" in Path("/etc/os-release").read_text().lower()
    except Exception:
        return False


# ── Tool registry ─────────────────────────────────────────────────────────────

TOOLS: dict[str, dict] = {
    "nmap": {
        "label": "Nmap",
        "desc": "Network port scanner",
        "check_cmd": ["nmap", "--version"],
        "version_parse": lambda o: next(
            (l.split("Nmap ")[1].split(" ")[0] for l in o.splitlines() if "Nmap " in l), None
        ),
        "apt_pkg": "nmap",
        "binary_url": None,
        "binary_name": None,
        "pip_pkg": None,
        "workflow": "nmap-scan.yml",
    },
    "gitleaks": {
        "label": "Gitleaks",
        "desc": "Git secret scanner — detects leaked credentials",
        "check_cmd": ["gitleaks", "version"],
        "version_parse": lambda o: o.strip().lstrip("v"),
        "apt_pkg": None,
        "binary_url": "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz",
        "binary_name": "gitleaks",
        "binary_archive": "tar",
        "pip_pkg": None,
        "workflow": "gitleaks-scan.yml",
    },
    "trivy": {
        "label": "Trivy",
        "desc": "Container and filesystem vulnerability scanner",
        "check_cmd": ["trivy", "--version"],
        "version_parse": lambda o: next(
            (l.split("Version: ")[1].strip() for l in o.splitlines() if "Version:" in l), None
        ),
        "apt_pkg": "trivy",
        "binary_url": "https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-64bit.tar.gz",
        "binary_name": "trivy",
        "binary_archive": "tar",
        "pip_pkg": None,
        "workflow": "trivy-scan.yml",
    },
    "trufflehog": {
        "label": "TruffleHog",
        "desc": "Deep secret scanner — finds secrets in git history",
        "check_cmd": ["trufflehog", "--version"],
        "version_parse": lambda o: o.strip().lstrip("trufflehog ").lstrip("v"),
        "apt_pkg": None,
        "binary_url": "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.1/trufflehog_3.88.1_linux_amd64.tar.gz",
        "binary_name": "trufflehog",
        "binary_archive": "tar",
        "pip_pkg": None,
        "workflow": "trufflehog-scan.yml",
    },
    "semgrep": {
        "label": "Semgrep",
        "desc": "Static analysis — finds bugs and security issues in source code",
        "check_cmd": ["semgrep", "--version"],
        "version_parse": lambda o: o.strip(),
        "apt_pkg": None,
        "binary_url": None,
        "binary_name": None,
        "pip_pkg": "semgrep",
        "workflow": "semgrep-scan.yml",
    },
    "nuclei": {
        "label": "Nuclei",
        "desc": "Template-based vulnerability scanner",
        "check_cmd": ["nuclei", "-version"],
        "version_parse": lambda o: next(
            (l.split("Nuclei Engine Version: ")[1].strip() for l in o.splitlines()
             if "Engine Version" in l), o.strip()
        ),
        "apt_pkg": None,
        "binary_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip",
        "binary_name": "nuclei",
        "binary_archive": "zip",
        "pip_pkg": None,
        "workflow": None,
    },
    "openvas": {
        "label": "OpenVAS / GVM",
        "desc": "Full vulnerability assessment scanner with NVT feed",
        "check_cmd": ["gvm-cli", "--version"],
        "version_parse": lambda o: o.strip(),
        "apt_pkg": "openvas",
        "binary_url": None,
        "binary_name": None,
        "pip_pkg": "gvm-tools",
        "workflow": None,
        "post_install": "gvm-setup",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _env_with_bin() -> dict:
    e = os.environ.copy()
    home_bin = str(Path.home() / ".local" / "bin")
    e["PATH"] = f"{OWLET_BIN}{os.pathsep}{home_bin}{os.pathsep}{e.get('PATH', '')}"
    return e


def _which(binary: str) -> Optional[str]:
    p = OWLET_BIN / binary
    if p.exists():
        return str(p)
    return shutil.which(binary, path=_env_with_bin()["PATH"])


def _probe(tool_name: str) -> dict:
    spec = TOOLS.get(tool_name, {})
    if not spec:
        return {"installed": False, "version": None, "binary_path": None}
    binary_path = _which(spec["check_cmd"][0])
    if not binary_path:
        return {"installed": False, "version": None, "binary_path": None}
    try:
        r = subprocess.run(
            spec["check_cmd"], capture_output=True, text=True,
            timeout=10, env=_env_with_bin(),
        )
        out = r.stdout or r.stderr or ""
        version = spec["version_parse"](out)
        return {"installed": True, "version": version, "binary_path": binary_path}
    except Exception:
        return {"installed": True, "version": None, "binary_path": binary_path}


def _upsert(db: Session, tool_name: str) -> LocalRunnerTool:
    row = db.query(LocalRunnerTool).filter(LocalRunnerTool.tool_name == tool_name).first()
    if not row:
        row = LocalRunnerTool(tool_name=tool_name, mode="github_actions")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def get_scanner_mode(tool_name: str) -> str:
    """Called by scans.py dispatch to check if a tool runs locally."""
    from db.database import SessionLocal
    db = SessionLocal()
    try:
        row = db.query(LocalRunnerTool).filter(LocalRunnerTool.tool_name == tool_name).first()
        return (row.mode if row else None) or "github_actions"
    finally:
        db.close()


# ── SSE install generator ─────────────────────────────────────────────────────

def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _install_stream(tool_name: str) -> AsyncGenerator[str, None]:
    spec = TOOLS.get(tool_name)
    if not spec:
        yield _sse({"error": f"Unknown tool: {tool_name}"})
        return

    OWLET_BIN.mkdir(parents=True, exist_ok=True)
    is_kali = _is_kali()

    # ── apt (prefer on Kali, also for tools that only have apt) ──────────────
    apt_pkg = spec.get("apt_pkg")
    if apt_pkg and (is_kali or not spec.get("binary_url")):
        yield _sse({"msg": f"Installing {apt_pkg} via apt-get (sudo)…"})
        # Always use sudo — the backend runs as a regular user and apt needs root
        proc = await asyncio.create_subprocess_exec(
            "sudo", "apt-get", "install", "-y", "-q", apt_pkg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if line:
                yield _sse({"line": line})
        await proc.wait()
        if proc.returncode != 0:
            # apt failed — fall through to binary download if available
            if not spec.get("binary_url") and not spec.get("pip_pkg"):
                yield _sse({"error": f"apt-get install {apt_pkg} failed. Run manually: sudo apt-get install -y {apt_pkg}"})
                return
            yield _sse({"msg": "apt-get failed — trying binary download instead…"})

    # ── pip ───────────────────────────────────────────────────────────────────
    pip_pkg = spec.get("pip_pkg")
    if pip_pkg:
        yield _sse({"msg": f"Installing {pip_pkg} via pip…"})
        # Use venv pip if available (avoids PEP 668 externally-managed error on Kali)
        _venv_pip = Path(__file__).parent.parent.parent.parent / "venv" / "bin" / "pip"
        _pip_cmd = str(_venv_pip) if _venv_pip.exists() else "pip3"
        proc = await asyncio.create_subprocess_exec(
            _pip_cmd, "install", pip_pkg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if line:
                yield _sse({"line": line})
        await proc.wait()
        if proc.returncode != 0:
            yield _sse({"error": f"pip3 install {pip_pkg} failed"})
            return

    # ── binary download (non-Kali or no apt package) ─────────────────────────
    binary_url = spec.get("binary_url")
    binary_name = spec.get("binary_name")
    archive_type = spec.get("binary_archive", "tar")

    if binary_url and binary_name and not _which(binary_name):
        yield _sse({"msg": f"Downloading {binary_name} from GitHub releases…"})
        tmp = Path(tempfile.mkdtemp(prefix="owlet_dl_"))
        try:
            archive_path = tmp / binary_url.split("/")[-1]
            yield _sse({"msg": f"Fetching {archive_path.name}…"})
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: urllib.request.urlretrieve(binary_url, archive_path)
            )
            yield _sse({"msg": "Extracting binary…"})
            dest = OWLET_BIN / binary_name
            if archive_type == "tar":
                with tarfile.open(archive_path) as tf:
                    member = next(
                        (m for m in tf.getmembers()
                         if m.name == binary_name or m.name.endswith(f"/{binary_name}")),
                        None,
                    )
                    if not member:
                        yield _sse({"error": f"'{binary_name}' not found in archive"})
                        return
                    member.name = binary_name
                    tf.extract(member, OWLET_BIN)
            else:  # zip
                with zipfile.ZipFile(archive_path) as zf:
                    match = next(
                        (n for n in zf.namelist()
                         if n == binary_name or n.endswith(f"/{binary_name}")),
                        None,
                    )
                    if not match:
                        yield _sse({"error": f"'{binary_name}' not found in zip"})
                        return
                    with zf.open(match) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            yield _sse({"msg": f"Installed to {dest}"})
        except Exception as exc:
            yield _sse({"error": str(exc)})
            return
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── OpenVAS post-install: gvm-setup ───────────────────────────────────────
    if spec.get("post_install") == "gvm-setup" and _which("gvm-setup"):
        yield _sse({"msg": "Running gvm-setup — this downloads the NVT feed (~20 min first time)…"})
        yield _sse({"msg": "You can close this window and come back; setup continues in the background."})
        proc = await asyncio.create_subprocess_exec(
            "sudo", "gvm-setup",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip()
            if line:
                yield _sse({"line": line})
        await proc.wait()
        if proc.returncode != 0:
            yield _sse({"msg": "gvm-setup finished with warnings — this is normal on first run."})

    # ── Final probe ───────────────────────────────────────────────────────────
    probe = _probe(tool_name)
    if probe["installed"]:
        yield _sse({"done": True, "version": probe["version"], "binary_path": probe["binary_path"]})
    else:
        yield _sse({
            "error": "Installation completed but tool binary not found on PATH. "
                     "You may need to restart the terminal / reload PATH.",
        })


# ── Request / response schemas ────────────────────────────────────────────────

class ModeUpdate(BaseModel):
    mode: str  # "local" | "github_actions"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def get_status(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Probe every tool and return install state + configured dispatch mode."""
    results = []
    for tool_name, spec in TOOLS.items():
        probe = _probe(tool_name)
        row = _upsert(db, tool_name)
        row.installed = probe["installed"]
        row.version = probe["version"]
        row.binary_path = probe["binary_path"]
        row.last_checked = datetime.now(timezone.utc)
        db.commit()
        results.append({
            "tool": tool_name,
            "label": spec["label"],
            "desc": spec["desc"],
            "installed": probe["installed"],
            "version": probe["version"],
            "binary_path": probe["binary_path"],
            "mode": row.mode,
            "has_local_exec": tool_name in ("nmap", "gitleaks", "trivy", "trufflehog", "semgrep", "openvas"),
        })
    return {"tools": results, "owlet_bin": str(OWLET_BIN), "is_kali": _is_kali()}


@router.get("/install/{tool}/stream")
async def stream_install(
    tool: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """SSE stream — install a tool and emit progress line by line."""
    if tool not in TOOLS:
        raise HTTPException(404, f"Unknown tool: {tool}")

    async def generate():
        async for chunk in _install_stream(tool):
            yield chunk
        # Refresh DB after install completes
        probe = _probe(tool)
        row = _upsert(db, tool)
        row.installed = probe["installed"]
        row.version = probe["version"]
        row.binary_path = probe["binary_path"]
        row.last_checked = datetime.now(timezone.utc)
        db.commit()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/config")
async def get_config(db: Session = Depends(get_db), _=Depends(get_current_user)):
    rows = {r.tool_name: r.mode for r in db.query(LocalRunnerTool).all()}
    return {t: rows.get(t, "github_actions") for t in TOOLS}


@router.patch("/config/{tool}")
async def update_config(
    tool: str,
    body: ModeUpdate,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    if tool not in TOOLS:
        raise HTTPException(404, f"Unknown tool: {tool}")
    if body.mode not in ("local", "github_actions"):
        raise HTTPException(400, "mode must be 'local' or 'github_actions'")
    row = _upsert(db, tool)
    if body.mode == "local" and not row.installed:
        raise HTTPException(400, f"{tool} is not installed — install it first")
    row.mode = body.mode
    db.commit()
    return {"tool": tool, "mode": body.mode}


@router.post("/test/{tool}")
async def test_tool(tool: str, _=Depends(get_current_user)):
    """Quick smoke-test to confirm a tool is reachable."""
    if tool not in TOOLS:
        raise HTTPException(404)
    probe = _probe(tool)
    if not probe["installed"]:
        raise HTTPException(400, f"{tool} is not installed")
    safe_tests: dict[str, list] = {
        "nmap":        ["nmap", "--version"],
        "gitleaks":    ["gitleaks", "version"],
        "trivy":       ["trivy", "--version"],
        "trufflehog":  ["trufflehog", "--version"],
        "semgrep":     ["semgrep", "--version"],
        "nuclei":      ["nuclei", "-version"],
        "openvas":     ["gvm-cli", "--version"],
    }
    cmd = safe_tests.get(tool, TOOLS[tool]["check_cmd"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=_env_with_bin())
        return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr or "")[:600]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "Timed out after 30s"}
    except Exception as exc:
        return {"ok": False, "output": str(exc)}


# ── Cloud portal pairing ──────────────────────────────────────────────────────

_CLOUD_LINK_FILE = Path.home() / ".owlet" / "cloud_link.json"


def _load_link() -> dict:
    try:
        return json.loads(_CLOUD_LINK_FILE.read_text())
    except Exception:
        return {}


def _save_link(data: dict) -> None:
    _CLOUD_LINK_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CLOUD_LINK_FILE.write_text(json.dumps(data, indent=2))


class CloudLinkRequest(BaseModel):
    cloud_url: str   # e.g. https://owlet-api.azurewebsites.net
    token: str       # the owlet_runner_... token from the cloud portal


@router.post("/cloud/link")
async def cloud_link(body: CloudLinkRequest, db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Register this local runner with the cloud portal using a pairing token."""
    cloud_url = body.cloud_url.rstrip("/")
    # Collect current tool status to send on registration
    tools_status = []
    for tool_name in TOOLS:
        probe = _probe(tool_name)
        row = db.query(LocalRunnerTool).filter(LocalRunnerTool.tool_name == tool_name).first()
        mode = (row.mode if row else None) or "github_actions"
        tools_status.append({
            "tool": tool_name,
            "installed": probe["installed"],
            "version": probe["version"],
            "mode": mode,
        })

    payload = {
        "machine_name": socket.gethostname(),
        "is_kali": _is_kali(),
        "tools": tools_status,
        "owlet_version": _get_version(),
    }

    try:
        import urllib.request as _ur, urllib.error
        req = _ur.Request(
            f"{cloud_url}/api/v1/runner-registry/register",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {body.token}",
            },
            method="POST",
        )
        with _ur.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
    except Exception as exc:
        raise HTTPException(502, f"Registration failed: {exc}")

    runner_id = result.get("runner_id")
    _save_link({"cloud_url": cloud_url, "token": body.token, "runner_id": runner_id})
    return {
        "ok": True,
        "runner_id": runner_id,
        "cloud_url": cloud_url,
        "message": result.get("message", "Registered successfully"),
    }


@router.get("/cloud/status")
async def cloud_status(_=Depends(get_current_user)):
    """Return the current cloud portal link status."""
    link = _load_link()
    if not link:
        return {"linked": False}
    return {
        "linked": True,
        "cloud_url": link.get("cloud_url"),
        "runner_id": link.get("runner_id"),
    }


@router.post("/cloud/heartbeat")
async def cloud_heartbeat(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Send a heartbeat with current tool status to the cloud portal."""
    link = _load_link()
    if not link:
        raise HTTPException(400, "Not linked to a cloud portal — call /cloud/link first")

    tools_status = []
    for tool_name in TOOLS:
        probe = _probe(tool_name)
        row = db.query(LocalRunnerTool).filter(LocalRunnerTool.tool_name == tool_name).first()
        mode = (row.mode if row else None) or "github_actions"
        tools_status.append({
            "tool": tool_name,
            "installed": probe["installed"],
            "version": probe["version"],
            "mode": mode,
        })

    cloud_url = link["cloud_url"].rstrip("/")
    runner_id = link["runner_id"]
    payload = {"tools": tools_status, "owlet_version": _get_version()}

    try:
        import urllib.request as _ur
        req = _ur.Request(
            f"{cloud_url}/api/v1/runner-registry/runners/{runner_id}/heartbeat",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {link['token']}",
            },
            method="PATCH",
        )
        with _ur.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
    except Exception as exc:
        raise HTTPException(502, f"Heartbeat failed: {exc}")

    return {"ok": True, "last_seen_at": result.get("last_seen_at")}


def _get_version() -> str:
    try:
        r = subprocess.run(
            ["git", "describe", "--tags", "--always"],
            capture_output=True, text=True, timeout=5,
            cwd=str(Path(__file__).parent.parent.parent.parent),
        )
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"
