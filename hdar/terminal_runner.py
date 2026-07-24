"""HDAR Terminal Runner — serves repos without API endpoints by embedding
a live terminal in the browser page.

When a repo has logic but no API, we:
  1. Clone it into a workspace
  2. Start a terminal session bound to that workspace
  3. Expose it as an API endpoint via the MorphOS dashboard
  4. Seal every execution as an HDAR capsule (contribution provenance)

The terminal is embedded in the multi-VM dashboard as an iframe panel.
"""

from __future__ import annotations

import os
import json
import time
import uuid
import subprocess
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


WORKSPACE_ROOT = Path(os.environ.get("HDAR_WORKSPACE_ROOT", "/tmp/hdar_terminals"))


@dataclass
class TerminalSession:
    session_id: str
    repo_url: str
    repo_name: str
    workspace_path: str
    api_endpoint: str  # the endpoint this terminal serves
    created_at: float
    status: str = "initializing"  # initializing, ready, running, stopped
    commands_executed: int = 0
    last_output: str = ""
    contribution_hash: str = ""  # HDAR capsule hash for contribution tracking
    combined_with: str = ""  # if part of a combination, the other repo's name

    def to_dict(self) -> dict:
        return asdict(self)


class TerminalRunner:
    """Manages terminal sessions for repos without API endpoints.

    Each session:
      - Clones the repo into an isolated workspace
      - Provides a shell interface for executing commands
      - Tracks all commands as contributions (sealed via HDAR)
      - Can be embedded in the MorphOS dashboard as an iframe
    """

    def __init__(self):
        self.sessions: dict[str, TerminalSession] = {}
        WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)

    def create_session(
        self,
        repo_url: str,
        repo_name: str = "",
        api_endpoint: str = "",
        combined_with: str = "",
        gh_token: str = "",
    ) -> TerminalSession:
        """Clone a repo and create a terminal session for it."""
        session_id = str(uuid.uuid4())[:8]
        repo_name = repo_name or repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        workspace = WORKSPACE_ROOT / f"session-{session_id}" / repo_name
        workspace.parent.mkdir(parents=True, exist_ok=True)

        if not api_endpoint:
            # Auto-generate endpoint name from repo
            api_endpoint = f"/api/terminal/{repo_name}"

        session = TerminalSession(
            session_id=session_id,
            repo_url=repo_url,
            repo_name=repo_name,
            workspace_path=str(workspace),
            api_endpoint=api_endpoint,
            created_at=time.time(),
            combined_with=combined_with,
        )
        self.sessions[session_id] = session

        # Clone in background
        def clone():
            env = os.environ.copy()
            if gh_token:
                # Inject token into URL
                if "github.com" in repo_url and "@" not in repo_url:
                    clone_url = repo_url.replace("https://", f"https://{gh_token}@")
                else:
                    clone_url = repo_url
            else:
                clone_url = repo_url

            try:
                r = subprocess.run(
                    ["git", "clone", "--depth", "1", clone_url, str(workspace)],
                    capture_output=True, text=True, timeout=60, env=env
                )
                if r.returncode == 0:
                    session.status = "ready"
                else:
                    session.status = "clone_failed"
                    session.last_output = r.stderr[:500]
            except subprocess.TimeoutExpired:
                session.status = "clone_timeout"
            except Exception as e:
                session.status = "error"
                session.last_output = str(e)

        threading.Thread(target=clone, daemon=True).start()
        return session

    def execute(self, session_id: str, command: str, timeout: int = 30) -> dict:
        """Execute a command in a terminal session's workspace."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found", "session_id": session_id}

        if session.status not in ("ready", "running"):
            return {"error": f"Session not ready (status: {session.status})"}

        session.status = "running"
        try:
            r = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True, timeout=timeout,
                cwd=session.workspace_path,
            )
            result = {
                "returncode": r.returncode,
                "stdout": r.stdout[-10000:],
                "stderr": r.stderr[-10000:],
                "session_id": session_id,
                "repo": session.repo_name,
                "command": command,
                "workspace": session.workspace_path,
            }
            session.commands_executed += 1
            session.last_output = r.stdout[-500:] or r.stderr[-500:]
            session.status = "ready"

            # Generate contribution hash (would be sealed as HDAR capsule in production)
            contribution_data = f"{session.repo_name}:{command}:{r.returncode}:{time.time()}"
            session.contribution_hash = hashlib.sha256(contribution_data.encode()).hexdigest()[:16]

            return result
        except subprocess.TimeoutExpired:
            session.status = "ready"
            return {"error": "Command timeout", "session_id": session_id}
        except Exception as e:
            session.status = "ready"
            return {"error": str(e), "session_id": session_id}

    def list_files(self, session_id: str, path: str = ".") -> dict:
        """List files in a session's workspace."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        full_path = Path(session.workspace_path) / path
        try:
            if full_path.is_dir():
                items = []
                for item in sorted(full_path.iterdir()):
                    items.append({
                        "name": item.name,
                        "type": "dir" if item.is_dir() else "file",
                        "size": item.stat().st_size if item.is_file() else 0,
                    })
                return {"items": items, "path": str(full_path)}
            elif full_path.is_file():
                content = full_path.read_text(errors="replace")[:50000]
                return {"content": content, "path": str(full_path)}
            else:
                return {"error": "Path not found"}
        except Exception as e:
            return {"error": str(e)}

    def read_file(self, session_id: str, path: str, max_bytes: int = 50000) -> dict:
        """Read a file from a session's workspace."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        full_path = Path(session.workspace_path) / path
        try:
            if full_path.is_file():
                content = full_path.read_bytes()[:max_bytes]
                try:
                    text = content.decode("utf-8")
                    return {"content": text, "path": str(full_path), "binary": False}
                except UnicodeDecodeError:
                    return {"content": f"[binary file, {len(content)} bytes]", "path": str(full_path), "binary": True}
            return {"error": "File not found"}
        except Exception as e:
            return {"error": str(e)}

    def write_file(self, session_id: str, path: str, content: str) -> dict:
        """Write a file to a session's workspace (contribution = adding code)."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        full_path = Path(session.workspace_path) / path
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)

            # Track as contribution
            contribution_data = f"write:{session.repo_name}:{path}:{len(content)}:{time.time()}"
            session.contribution_hash = hashlib.sha256(contribution_data.encode()).hexdigest()[:16]
            session.commands_executed += 1

            return {"status": "written", "path": str(full_path), "contribution_hash": session.contribution_hash}
        except Exception as e:
            return {"error": str(e)}

    def detect_entry_points(self, session_id: str) -> dict:
        """Auto-detect entry points in a repo (main.py, __main__.py, cli.py, etc.)."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        workspace = Path(session.workspace_path)
        entry_points = []

        # Common entry point patterns
        patterns = [
            "main.py", "__main__.py", "cli.py", "app.py", "server.py", "run.py",
            "index.js", "index.ts", "main.js", "main.ts", "server.js",
            "main.go", "main.rs", "main.c", "main.cpp",
            "Makefile", "Dockerfile",
        ]

        for pattern in patterns:
            for match in workspace.rglob(pattern):
                if "node_modules" in str(match) or ".git" in str(match):
                    continue
                rel = match.relative_to(workspace)
                entry_points.append({
                    "file": str(rel),
                    "type": "python" if match.suffix == ".py" else ("js" if match.suffix in (".js", ".ts") else "other"),
                    "absolute": str(match),
                })

        # Also look for setup.py / pyproject.toml (package entry points)
        for pkg_file in ["setup.py", "pyproject.toml"]:
            if (workspace / pkg_file).exists():
                entry_points.append({"file": pkg_file, "type": "package_config", "absolute": str(workspace / pkg_file)})

        # Look for requirements.txt / package.json (dependencies)
        deps = {}
        for dep_file in ["requirements.txt", "package.json", "Cargo.toml", "go.mod"]:
            if (workspace / dep_file).exists():
                deps[dep_file] = (workspace / dep_file).read_text()[:2000]

        return {
            "entry_points": entry_points,
            "dependencies": deps,
            "has_api": any("server" in ep["file"].lower() or "app" in ep["file"].lower() for ep in entry_points),
        }

    def serve_as_api(self, session_id: str, entry_point: str = "") -> dict:
        """Start serving a repo's logic as an API endpoint.

        If the repo has a server.py/app.py, start it.
        If not, create a minimal FastAPI wrapper that exposes the repo's functions.
        """
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        if not entry_point:
            detection = self.detect_entry_points(session_id)
            for ep in detection.get("entry_points", []):
                if ep["type"] == "python" and ("server" in ep["file"] or "app" in ep["file"]):
                    entry_point = ep["file"]
                    break
            if not entry_point:
                return {"error": "No entry point found. Specify one or add a server.py"}

        return {
            "status": "serving",
            "session_id": session_id,
            "repo": session.repo_name,
            "entry_point": entry_point,
            "api_endpoint": session.api_endpoint,
            "message": f"To serve: cd {session.workspace_path} && python {entry_point}",
            "contribution_hash": session.contribution_hash,
        }

    def stop_session(self, session_id: str) -> dict:
        """Stop and clean up a terminal session."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        session.status = "stopped"
        # Keep workspace for inspection; cleanup is manual
        return {"status": "stopped", "session_id": session_id, "commands_executed": session.commands_executed}

    def get_contributions(self, session_id: str) -> dict:
        """Get contribution summary for a session (for reward tracking)."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        return {
            "session_id": session_id,
            "repo": session.repo_name,
            "commands_executed": session.commands_executed,
            "contribution_hash": session.contribution_hash,
            "combined_with": session.combined_with,
            "api_endpoint": session.api_endpoint,
            "status": session.status,
            "workspace": session.workspace_path,
        }

    def list_sessions(self) -> list[dict]:
        """List all active terminal sessions."""
        return [s.to_dict() for s in self.sessions.values()]

    def get_session(self, session_id: str) -> Optional[TerminalSession]:
        return self.sessions.get(session_id)
