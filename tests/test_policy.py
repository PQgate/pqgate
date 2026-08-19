"""Policy engine semantics — every behavior in the spec gets a test."""
import datetime
import subprocess

import pytest
import yaml

from pqgate.policy import (PolicyError, apply_policy, exception_register,
                               git_changed_files, load_policy, match_paths)
from pqgate.profiles import ProfileError

TODAY = datetime.date(2026, 8, 18)


def finding(**kw):
    base = {"rule": "py-rsa-keygen", "classification": "quantum-vulnerable",
            "message": "RSA key generation", "file": "app/keys.py", "line": 5,
            "evidence": "rsa.generate_private_key(...)", "detector": "ast"}
    base.update(kw)
    return base


def write_policy(tmp_path, doc):
    path = tmp_path / ".pqgate.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------
# Profile defaults
# --------------------------------------------------------------------------
def test_profile_default_action_applies():
    kept, notes = apply_policy([finding()], load_policy(None), today=TODAY)
    assert kept[0]["action"] == "block"
    assert kept[0]["policy_id"] == "profile:cnsa-2.0"
    assert notes == []


def test_baseline_profile_downgrades_quantum_vulnerable():
    pol = load_policy(None, profile_override="nist-baseline")
    kept, _ = apply_policy([finding()], pol, today=TODAY)
    assert kept[0]["action"] == "warn"


def test_unknown_profile_rejected():
    with pytest.raises(ProfileError):
        load_policy(None, profile_override="does-not-exist")


# --------------------------------------------------------------------------
# Custom policies
# --------------------------------------------------------------------------
def test_policy_override_by_algorithm(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "profile": "nist-baseline",
        "policies": [{"id": "no-new-rsa", "match": {"algorithm": "RSA"}, "action": "block"}],
    }))
    kept, _ = apply_policy([finding()], pol, today=TODAY)
    assert kept[0]["action"] == "block"
    assert kept[0]["policy_id"] == "no-new-rsa"


def test_policy_paths_scoping(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "legacy-warn", "match": {"algorithm": "RSA"},
                      "paths": ["legacy/**"], "action": "warn"}],
    }))
    inside = finding(file="legacy/payments.py")
    outside = finding(file="app/keys.py")
    kept, _ = apply_policy([inside, outside], pol, today=TODAY)
    assert kept[0]["action"] == "warn" and kept[0]["policy_id"] == "legacy-warn"
    assert kept[1]["action"] == "block" and kept[1]["policy_id"] == "profile:cnsa-2.0"


def test_last_matching_policy_wins(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [
            {"id": "first", "match": {"classification": "quantum-vulnerable"}, "action": "warn"},
            {"id": "second", "match": {"classification": "quantum-vulnerable"}, "action": "block"},
        ],
    }))
    kept, _ = apply_policy([finding()], pol, today=TODAY)
    assert kept[0]["policy_id"] == "second" and kept[0]["action"] == "block"


def test_match_on_rule_id(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "go-only", "match": {"rule": "go-*"}, "action": "warn"}],
    }))
    kept, _ = apply_policy([finding(rule="go-rsa-keygen"), finding()], pol, today=TODAY)
    assert kept[0]["action"] == "warn"
    assert kept[1]["action"] == "block"


def test_policy_needs_match_or_paths(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(write_policy(tmp_path, {"policies": [{"id": "empty", "action": "block"}]}))


def test_duplicate_policy_ids_rejected(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(write_policy(tmp_path, {"policies": [
            {"id": "x", "match": {"algorithm": "RSA"}, "action": "block"},
            {"id": "x", "match": {"algorithm": "EC"}, "action": "warn"},
        ]}))


def test_invalid_scope_rejected(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(write_policy(tmp_path, {"policies": [
            {"id": "x", "match": {"algorithm": "RSA"}, "scope": "sometimes"}]}))


# --------------------------------------------------------------------------
# new-code-only scoping
# --------------------------------------------------------------------------
def test_new_code_only_applies_to_changed_files(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "profile": "nist-baseline",
        "policies": [{"id": "new-rsa", "match": {"algorithm": "RSA"},
                      "scope": "new-code-only", "action": "block"}],
    }))
    changed, unchanged = finding(file="new.py"), finding(file="old.py")
    kept, _ = apply_policy([changed, unchanged], pol, changed_files={"new.py"}, today=TODAY)
    assert kept[0]["action"] == "block"
    assert kept[1]["action"] == "warn"


def test_new_code_only_without_diff_base_emits_note(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "new-rsa", "match": {"algorithm": "RSA"},
                      "scope": "new-code-only", "action": "warn"}],
    }))
    kept, notes = apply_policy([finding()], pol, changed_files=None, today=TODAY)
    assert kept[0]["action"] == "block", "policy must not silently apply"
    assert any("new-code-only" in n for n in notes)


def test_git_changed_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo)] + list(a),
                                    capture_output=True, text=True, check=True)
    run("init", "-q", "-b", "main")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n")
    run("add", "-A")
    run("commit", "-qm", "base")
    (repo / "b.py").write_text("y = 2\n")
    run("add", "-A")
    run("commit", "-qm", "second")
    changed = git_changed_files(str(repo), "HEAD~1")
    assert any(p.endswith("b.py") for p in changed)
    assert not any(p.endswith("a.py") for p in changed)


def test_git_diff_failure_is_an_error(tmp_path):
    with pytest.raises(PolicyError):
        git_changed_files(str(tmp_path), "no-such-ref")


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------
def test_valid_exception_suppresses_finding(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "no-new-rsa", "match": {"algorithm": "RSA"}, "action": "block"}],
        "exceptions": [{"policy": "no-new-rsa", "paths": ["legacy/**"],
                        "reason": "SEC-142", "expires": "2027-06-30"}],
    }))
    kept, notes = apply_policy([finding(file="legacy/payments.py")], pol, today=TODAY)
    assert kept == []
    assert notes == []


def test_expired_exception_restores_enforcement(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "no-new-rsa", "match": {"algorithm": "RSA"}, "action": "block"}],
        "exceptions": [{"policy": "no-new-rsa", "paths": ["legacy/**"],
                        "reason": "SEC-142", "expires": "2025-01-01"}],
    }))
    kept, notes = apply_policy([finding(file="legacy/payments.py")], pol, today=TODAY)
    assert kept[0]["action"] == "block"
    assert len(notes) == 1 and "EXPIRED" in notes[0]


def test_expired_exception_note_is_emitted_once(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "policies": [{"id": "no-new-rsa", "match": {"algorithm": "RSA"}, "action": "block"}],
        "exceptions": [{"policy": "no-new-rsa", "paths": ["legacy/**"],
                        "reason": "r", "expires": "2025-01-01"}],
    }))
    findings = [finding(file="legacy/a.py"), finding(file="legacy/b.py"),
                finding(file="legacy/c.py")]
    _, notes = apply_policy(findings, pol, today=TODAY)
    assert len(notes) == 1


def test_exception_requires_reason(tmp_path):
    with pytest.raises(PolicyError, match="reason"):
        load_policy(write_policy(tmp_path, {"exceptions": [
            {"policy": "*", "expires": "2027-01-01"}]}))


def test_exception_requires_expiry(tmp_path):
    with pytest.raises(PolicyError, match="expires"):
        load_policy(write_policy(tmp_path, {"exceptions": [
            {"policy": "*", "reason": "because"}]}))


def test_exception_bad_date_rejected(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(write_policy(tmp_path, {"exceptions": [
            {"policy": "*", "reason": "r", "expires": "soon"}]}))


def test_wildcard_exception_matches_any_policy(tmp_path):
    pol = load_policy(write_policy(tmp_path, {
        "exceptions": [{"policy": "*", "paths": ["thirdparty/**"],
                        "reason": "vendor code", "expires": "2030-01-01"}],
    }))
    kept, _ = apply_policy([finding(file="thirdparty/x.py"), finding()], pol, today=TODAY)
    assert [f["file"] for f in kept] == ["app/keys.py"]


def test_exception_register_sorted_by_days_left(tmp_path):
    pol = load_policy(write_policy(tmp_path, {"exceptions": [
        {"policy": "a", "reason": "r", "expires": "2030-01-01"},
        {"policy": "b", "reason": "r", "expires": "2027-01-01"},
        {"policy": "c", "reason": "r", "expires": "2025-01-01"},
    ]}))
    rows = exception_register(pol, today=TODAY)
    assert [r["policy"] for r in rows] == ["c", "b", "a"]
    assert rows[0]["expired"] is True
    assert rows[1]["days_left"] > 0


# --------------------------------------------------------------------------
@pytest.mark.parametrize("path,patterns,expected", [
    ("legacy/payments.py", ["legacy/**"], True),
    ("demo-repo/legacy/payments.py", ["legacy/**"], True),
    ("demo-repo\\legacy\\payments.py", ["legacy/**"], True),
    ("app/keys.py", ["legacy/**"], False),
    ("legacy/old_hash.py", ["legacy/old_hash.py"], True),
    ("src/a.py", ["*.py"], True),
])
def test_match_paths(path, patterns, expected):
    assert match_paths(path, patterns) is expected


def test_default_policy_is_not_mutated(tmp_path):
    load_policy(write_policy(tmp_path, {"policies": [
        {"id": "x", "match": {"algorithm": "RSA"}, "action": "warn"}]}))
    fresh = load_policy(None)
    assert fresh["policies"] == []


def test_match_paths_is_platform_independent():
    """A backslash path must match on Linux too.

    match_paths normalised with os.sep, so an exception authored on Windows matched
    there and silently stopped matching on the Linux runner that gates the merge -
    the finding would block, with nothing pointing at why.
    """
    assert match_paths(r"demo-repo\legacy\payments.py", ["legacy/**"]) is True
    assert match_paths("demo-repo/legacy/payments.py", ["legacy/**"]) is True
    assert match_paths("app/keys.py", ["legacy/**"]) is False
