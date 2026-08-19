"""Release 0.2 Definition of Done, demonstrated end to end on a real git repo:

  a PR introducing rsa.GenerateKey is blocked, the SARIF annotation lands on the exact
  line, the sticky comment shows the CBOM diff, and an expired exception visibly
  restores enforcement.
"""
import importlib.util
import json
import os
import subprocess

import pytest

from pqgate import EXIT_BLOCKED, EXIT_PASS
from pqgate.cli import main

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_spec = importlib.util.spec_from_file_location(
    "pr_comment_int", os.path.join(ROOT, "action", "pr_comment.py"))
pr_comment = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr_comment)

CLEAN_GO = """package tls

import "crypto/sha512"

func Digest(b []byte) []byte {
\th := sha512.New384()
\treturn h.Sum(b)
}
"""

PR_GO = """package tls

import (
\t"crypto/rand"
\t"crypto/rsa"
\t"crypto/sha512"
)

func Digest(b []byte) []byte {
\th := sha512.New384()
\treturn h.Sum(b)
}

func NewKey() (*rsa.PrivateKey, error) {
\treturn rsa.GenerateKey(rand.Reader, 2048)
}
"""

# The real CNSA migration pattern: existing RSA is tracked debt, new RSA is blocked.
# Order matters - the last matching policy wins.
POLICY = """version: 1
profile: cnsa-2.0
policies:
  - id: rsa-debt
    match: { algorithm: RSA }
    scope: all-code
    action: warn
  - id: no-new-rsa
    match: { algorithm: RSA }
    scope: new-code-only
    action: block
reporting:
  fail_build_on: block
"""


def git(repo, *args):
    proc = subprocess.run(["git", "-C", str(repo)] + list(args),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture()
def pr_repo(tmp_path):
    """A repo whose HEAD commit is 'the PR': it introduces rsa.GenerateKey."""
    repo = tmp_path / "svc"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "ci@example.com")
    git(repo, "config", "user.name", "ci")
    (repo / ".pqgate.yml").write_text(POLICY, encoding="utf-8")
    (repo / "tls.go").write_text(CLEAN_GO, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    (repo / "tls.go").write_text(PR_GO, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "add key generation")
    return repo


def run(*argv):
    return main(["--no-color", *argv])


def test_pr_introducing_rsa_is_blocked(pr_repo, tmp_path, capsys):
    sarif_path = tmp_path / "r.sarif"
    code = run("scan", str(pr_repo), "--diff-base", "HEAD~1", "--sarif", str(sarif_path))
    assert code == EXIT_BLOCKED
    assert "GATE: BLOCKED" in capsys.readouterr().out

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "go-rsa-keygen"]
    assert len(results) == 1
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "tls.go"
    assert loc["region"]["startLine"] == PR_GO.splitlines().index(
        "\treturn rsa.GenerateKey(rand.Reader, 2048)") + 1
    assert results[0]["level"] == "error"


def test_unchanged_files_stay_migration_debt(pr_repo, tmp_path, capsys):
    """new-code-only escalates only what the PR touched; old RSA stays a warning."""
    (pr_repo / "legacy.go").write_text(PR_GO.replace("NewKey", "OldKey"), encoding="utf-8")
    git(pr_repo, "add", "-A")
    git(pr_repo, "commit", "-qm", "add legacy file")
    (pr_repo / "README.md").write_text("docs only\n", encoding="utf-8")
    git(pr_repo, "add", "-A")
    git(pr_repo, "commit", "-qm", "docs only PR")

    # This PR touched nothing but docs, so neither RSA site is newly introduced.
    assert run("scan", str(pr_repo), "--diff-base", "HEAD~1") == EXIT_PASS
    out = capsys.readouterr().out
    assert out.count("WARN ") == 2 and "BLOCK" not in out
    assert "rsa-debt" in out


def test_sticky_comment_shows_the_cbom_diff(pr_repo, tmp_path):
    base_cbom, pr_cbom = tmp_path / "base.json", tmp_path / "pr.json"
    git(pr_repo, "worktree", "add", "-q", str(tmp_path / "base"), "HEAD~1")
    run("scan", str(tmp_path / "base"), "--fail-on", "never", "--cbom", str(base_cbom))
    run("scan", str(pr_repo), "--diff-base", "HEAD~1", "--cbom", str(pr_cbom))

    body = pr_comment.build_body(json.loads(pr_cbom.read_text(encoding="utf-8")),
                                 json.loads(base_cbom.read_text(encoding="utf-8")))
    assert "gate BLOCKED" in body
    assert "| + | `go-rsa-keygen` | `tls.go` |" in body


def test_expired_exception_restores_enforcement(pr_repo, capsys):
    valid = POLICY + """exceptions:
  - policy: no-new-rsa
    paths: ["tls.go"]
    reason: "Vendor handshake constraint, SEC-311"
    expires: 2099-01-01
"""
    (pr_repo / ".pqgate.yml").write_text(valid, encoding="utf-8")
    assert run("scan", str(pr_repo), "--diff-base", "HEAD~1") == EXIT_PASS

    expired = valid.replace("2099-01-01", "2025-01-01")
    (pr_repo / ".pqgate.yml").write_text(expired, encoding="utf-8")
    assert run("scan", str(pr_repo), "--diff-base", "HEAD~1") == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "EXPIRED 2025-01-01" in out and "enforcement restored" in out


def test_exception_shows_in_register_and_cbom(pr_repo, tmp_path, capsys):
    (pr_repo / ".pqgate.yml").write_text(POLICY + """exceptions:
  - policy: no-new-rsa
    paths: ["tls.go"]
    reason: "Vendor handshake constraint, SEC-311"
    expires: 2027-01-01
""", encoding="utf-8")
    cbom = tmp_path / "c.json"
    run("scan", str(pr_repo), "--diff-base", "HEAD~1", "--cbom", str(cbom))
    capsys.readouterr()  # drop the scan output before capturing the JSON
    register = json.loads(cbom.read_text(encoding="utf-8"))["metadata"]["exceptions"]
    assert register[0]["reason"] == "Vendor handshake constraint, SEC-311"
    assert register[0]["expired"] is False

    run("exceptions", str(pr_repo), "--json")
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["policy"] == "no-new-rsa"
