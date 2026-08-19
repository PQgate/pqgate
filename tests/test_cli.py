"""CLI contract: exit codes 0 pass / 1 blocked / 2 error, and artifact writing."""
import json
import os
import subprocess
import sys

import pytest

from pqgate import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS
from pqgate.cli import main

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMO = os.path.join(ROOT, "demo-repo")


def run(*argv):
    """Call main() in-process; it returns the exit code instead of raising."""
    return main(["--no-color", *argv])


def test_scan_blocks_on_violations(capsys):
    assert run("scan", DEMO) == EXIT_BLOCKED
    out = capsys.readouterr().out
    assert "GATE: BLOCKED" in out
    assert "quantum-readiness score: 27/100" in out


def test_scan_passes_on_clean_tree(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("import hashlib\nh = hashlib.sha384(b'x')\n", encoding="utf-8")
    assert run("scan", str(tmp_path)) == EXIT_PASS
    assert "GATE: PASS" in capsys.readouterr().out


def test_fail_on_never_still_reports(tmp_path, capsys):
    assert run("scan", DEMO, "--fail-on", "never") == EXIT_PASS
    assert "GATE: BLOCKED" in capsys.readouterr().out


def test_fail_on_warn_blocks_on_warnings(tmp_path, capsys):
    (tmp_path / "a.py").write_text("k = oqs.KeyEncapsulation('ML-KEM-768')\n", encoding="utf-8")
    assert run("scan", str(tmp_path)) == EXIT_PASS
    assert run("scan", str(tmp_path), "--fail-on", "warn") == EXIT_BLOCKED


def test_scan_missing_directory_is_an_error():
    with pytest.raises(SystemExit) as exc:
        run("scan", os.path.join(ROOT, "does-not-exist"))
    assert exc.value.code == EXIT_ERROR


def test_unknown_profile_is_an_error():
    with pytest.raises(SystemExit) as exc:
        run("scan", DEMO, "--profile", "nope")
    assert exc.value.code == EXIT_ERROR


def test_profile_override_changes_outcome(tmp_path):
    (tmp_path / "a.py").write_text("k = rsa.generate_private_key(65537, 2048)\n", encoding="utf-8")
    assert run("scan", str(tmp_path)) == EXIT_BLOCKED
    assert run("scan", str(tmp_path), "--profile", "nist-baseline") == EXIT_PASS


def test_scan_writes_cbom_and_sarif(tmp_path):
    cbom = tmp_path / "c.json"
    sarif = tmp_path / "s.sarif"
    run("scan", DEMO, "--cbom", str(cbom), "--sarif", str(sarif))
    doc = json.loads(cbom.read_text(encoding="utf-8"))
    # 27, not 33: the demo repo also depends on two non-CMVP-validated modules, which
    # the SC-12 layer now records as migration debt.
    assert doc["metadata"]["score"] == 27
    assert doc["metadata"]["counts"] == {"block": 5, "warn": 3, "pass": 3}
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_scan_matches_prototype_posture():
    """Release 0.1 DoD: same findings and score as the v0.3 prototype on demo-repo."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cbom = os.path.join(d, "c.json")
        run("scan", DEMO, "--cbom", cbom)
        with open(cbom, encoding="utf-8") as fh:
            doc = json.load(fh)
    blocks = {c["evidence"]["occurrences"][0]["location"]
              for c in doc["components"] if c["cryptoProperties"]["action"] == "block"}
    assert blocks == {"requirements.txt", "src/Signer.java", "auth/newfeat.py",
                      "auth/keys.py", "legacy/old_hash.py"}


def test_report_and_verify_roundtrip(tmp_path):
    cbom = tmp_path / "c.json"
    report = tmp_path / "r.md"
    pdf = tmp_path / "r.pdf"
    run("scan", DEMO, "--cbom", str(cbom))
    assert run("report", str(cbom), "--org", "Raven Defense Systems",
               "--out", str(report), "--pdf", str(pdf)) == EXIT_PASS
    assert "Raven Defense Systems" in report.read_text(encoding="utf-8")
    assert pdf.read_bytes().startswith(b"%PDF")
    assert run("verify", str(report), str(cbom)) == EXIT_PASS


def test_verify_detects_tampering(tmp_path):
    cbom = tmp_path / "c.json"
    run("scan", DEMO, "--cbom", str(cbom))
    doc = json.loads(cbom.read_text(encoding="utf-8"))
    doc["metadata"]["score"] = 100
    cbom.write_text(json.dumps(doc), encoding="utf-8")
    assert run("verify", str(cbom)) == EXIT_BLOCKED


def test_diff_command(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "x.py").write_text("k = rsa.generate_private_key(65537, 2048)\n", encoding="utf-8")
    run("scan", str(tmp_path / "src"), "--cbom", str(a))
    (tmp_path / "src" / "x.py").write_text("k = oqs.KeyEncapsulation('ML-KEM-1024')\n", encoding="utf-8")
    run("scan", str(tmp_path / "src"), "--cbom", str(b))
    assert run("diff", str(a), str(b)) == EXIT_PASS
    out = capsys.readouterr().out
    assert "+ py-pqc-oqs" in out and "- py-rsa-keygen" in out


def test_exceptions_command_json(capsys):
    assert run("exceptions", DEMO, "--json") == EXIT_PASS
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["expired"] is True, "soonest expiry first"
    assert {r["policy"] for r in rows} == {"cnsa-2.0", "no-new-rsa"}


def test_exceptions_command_table(capsys):
    assert run("exceptions", DEMO) == EXIT_PASS
    out = capsys.readouterr().out
    assert "EXPIRED" in out and "SEC-142" in out


def test_rules_command_lists_every_rule(capsys):
    assert run("rules", "--json") == EXIT_PASS
    rules = json.loads(capsys.readouterr().out)
    assert len(rules) >= 23
    assert any(r["ast"] for r in rules), "Python rules use the AST detector"


def test_profiles_command(capsys):
    assert run("profiles") == EXIT_PASS
    out = capsys.readouterr().out
    assert "cnsa-2.0" in out and "nist-baseline" in out


def test_custom_profile_from_directory(tmp_path, capsys):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "lenient.yml").write_text(
        "name: lenient\nextends: cnsa-2.0\nactions:\n  quantum-vulnerable: warn\n"
        "  weak-hash: warn\n", encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("k = rsa.generate_private_key(65537, 2048)\n", encoding="utf-8")
    assert run("--profiles-dir", str(profiles), "scan", str(src), "--profile", "lenient") == EXIT_PASS


def test_module_entrypoint_exit_code():
    proc = subprocess.run([sys.executable, "-m", "pqgate", "--no-color", "scan", DEMO],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == EXIT_BLOCKED
    assert "GATE: BLOCKED" in proc.stdout


def test_push_failure_does_not_mask_gate_result(capsys):
    """A dead evidence server must not turn a blocked gate into a pass, or vice versa."""
    assert run("scan", DEMO, "--push", "http://127.0.0.1:9", "--token", "x") == EXIT_BLOCKED
    captured = capsys.readouterr()
    assert "PUSH  -> FAILED" in captured.err


def test_global_flags_accepted_after_the_subcommand():
    """`pqgate scan . --no-color` must work, not just `pqgate --no-color scan .`.

    argparse puts global options before the subcommand, but nobody types them there.
    Our own CI workflow was written the natural way and failed with "unrecognized
    arguments" - a flag that only works in one position is a defect, not a convention.
    """
    from pqgate.cli import build_parser
    ap = build_parser()
    for argv in (["--no-color", "scan", "."], ["scan", ".", "--no-color"]):
        assert getattr(ap.parse_args(argv), "no_color") is True, argv
    # ...and absent means absent, in either arrangement.
    assert getattr(ap.parse_args(["scan", "."]), "no_color") is False
