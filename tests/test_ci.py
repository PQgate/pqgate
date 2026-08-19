"""CI integration surfaces: sticky PR comment body and the GitLab report converter."""
import importlib.util
import json
import os
import subprocess
import sys

from pqgate.outputs import build_cbom, build_sarif

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pr_comment = _load("action/pr_comment.py", "pr_comment")
sarif_to_gitlab = _load(".gitlab/sarif_to_gitlab.py", "sarif_to_gitlab")


def finding(action="block", **kw):
    base = {"rule": "py-rsa-keygen", "classification": "quantum-vulnerable",
            "message": "RSA key generation", "file": "auth/keys.py", "line": 5,
            "evidence": "rsa.generate_private_key(...)", "detector": "ast",
            "action": action, "policy_id": "no-new-rsa"}
    base.update(kw)
    return base


# --------------------------------------------------------------------------
def test_comment_reports_blocked_gate():
    body = pr_comment.build_body(build_cbom([finding()], ".", "cnsa-2.0"), None)
    assert pr_comment.MARKER in body
    assert "gate BLOCKED" in body
    assert "| Blocking violations | 1 |" in body


def test_comment_reports_passing_gate():
    body = pr_comment.build_body(build_cbom([finding(action="pass")], ".", "cnsa-2.0"), None)
    assert "gate passed" in body
    assert "**100/100**" in body


def test_comment_includes_cbom_diff():
    old = build_cbom([finding()], ".", "cnsa-2.0")
    new = build_cbom([finding(action="pass", rule="py-pqc-oqs", classification="pqc-safe",
                              file="auth/kem.py")], ".", "cnsa-2.0")
    body = pr_comment.build_body(new, old)
    assert "Cryptographic changes in this PR" in body
    assert "py-pqc-oqs" in body and "py-rsa-keygen" in body


def test_comment_surfaces_expiring_exceptions():
    cbom = build_cbom([finding()], ".", "cnsa-2.0", exceptions=[
        {"policy": "no-new-rsa", "paths": ["legacy/**"], "reason": "SEC-142",
         "expires": "2026-09-10", "days_left": 23, "expired": False},
        {"policy": "quiet", "paths": ["x/**"], "reason": "later",
         "expires": "2030-01-01", "days_left": 1200, "expired": False},
    ])
    body = pr_comment.build_body(cbom, None)
    assert "SEC-142" in body and "23 days left" in body
    assert "later" not in body, "far-future exceptions should not add noise"


def test_comment_marker_makes_it_sticky():
    a = pr_comment.build_body(build_cbom([finding()], ".", "cnsa-2.0"), None)
    b = pr_comment.build_body(build_cbom([finding(action="pass")], ".", "cnsa-2.0"), None)
    assert a.startswith(pr_comment.MARKER) and b.startswith(pr_comment.MARKER)


def test_comment_dry_run_cli(tmp_path):
    path = tmp_path / "cbom.json"
    path.write_text(json.dumps(build_cbom([finding()], ".", "cnsa-2.0")), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "action", "pr_comment.py"), "--cbom", str(path),
         "--repo", "raven/avionics", "--pr", "1", "--dry-run"],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert pr_comment.MARKER in proc.stdout


# --------------------------------------------------------------------------
def test_gitlab_report_shape():
    findings = [finding(), finding(action="warn", rule="py-pqc-oqs",
                                   classification="pqc-below-profile", file="auth/kem.py", line=11)]
    report = sarif_to_gitlab.convert(build_sarif(findings, "."))
    assert report["version"] == "15.0.7"
    assert report["scan"]["type"] == "sast"
    assert len(report["vulnerabilities"]) == 2
    assert [v["severity"] for v in report["vulnerabilities"]] == ["Critical", "Medium"]
    assert report["vulnerabilities"][0]["location"] == {
        "file": "auth/keys.py", "start_line": 5, "end_line": 5}


def test_gitlab_ids_are_deterministic():
    sarif = build_sarif([finding()], ".")
    assert (sarif_to_gitlab.convert(sarif)["vulnerabilities"][0]["id"]
            == sarif_to_gitlab.convert(sarif)["vulnerabilities"][0]["id"])


def test_gitlab_converter_cli(tmp_path):
    sarif_path = tmp_path / "r.sarif"
    out_path = tmp_path / "gl.json"
    sarif_path.write_text(json.dumps(build_sarif([finding()], ".")), encoding="utf-8")
    assert sarif_to_gitlab.main(["x", str(sarif_path), str(out_path)]) == 0
    assert json.loads(out_path.read_text(encoding="utf-8"))["vulnerabilities"]
