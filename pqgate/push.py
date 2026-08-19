"""Upload a CBOM to the evidence server.

The ONLY network call in the scanner, and only to an endpoint the operator names
explicitly with --push. Uses stdlib urllib so the binary keeps zero dependencies.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request


def _git(root, *args):
    try:
        proc = subprocess.run(["git", "-C", root] + list(args),
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_context(root):
    """Best-effort repo/branch/commit for the scan target. Never fatal."""
    remote = _git(root, "config", "--get", "remote.origin.url")
    repo = None
    if remote:
        repo = remote.rstrip("/").removesuffix(".git").split("/")[-1]
    return {
        "repo": repo or os.path.basename(os.path.abspath(root)),
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "commit": _git(root, "rev-parse", "HEAD"),
    }


def push_cbom(base_url, token, cbom, repo=None, branch=None, commit=None,
              org=None, timeout=15):
    target = cbom.get("metadata", {}).get("target", ".")
    ctx = git_context(target if os.path.isdir(target) else ".")
    payload = {
        "repo": repo or ctx["repo"],
        "branch": branch or ctx["branch"] or "unknown",
        "commit": commit or ctx["commit"] or "unknown",
        "org": org or "Default Organization",
        "cbom": cbom,
    }
    req = urllib.request.Request(
        base_url.rstrip("/") + "/api/scans",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + (token or "")},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError("HTTP " + str(exc.code) + ": " + exc.read().decode("utf-8", "ignore")[:200]) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("cannot reach " + base_url + ": " + str(exc.reason)) from exc
