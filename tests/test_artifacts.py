"""CBOM, SARIF, diff and readiness-report artifacts — the evidence contract."""
import copy
import json
import os

import jsonschema
import pytest

from pqgate.outputs import (build_cbom, build_sarif, cbom_delta, content_hash,
                                markdown_diff, readiness_report_markdown, score,
                                verify_cbom, verify_report)

HERE = os.path.dirname(os.path.abspath(__file__))
SARIF_SCHEMA = os.path.join(HERE, "data", "sarif-2.1.0.schema.json")


def finding(action="block", **kw):
    base = {"rule": "py-rsa-keygen", "classification": "quantum-vulnerable",
            "message": "RSA key generation", "file": "app/keys.py", "line": 5,
            "evidence": "rsa.generate_private_key(...)", "detector": "ast",
            "action": action, "policy_id": "no-new-rsa"}
    base.update(kw)
    return base


FINDINGS = [
    finding(),
    finding(action="warn", rule="py-pqc-oqs", classification="pqc-below-profile",
            message="PQC below profile", file="app/kem.py", line=11),
    finding(action="pass", rule="java-pqc-bc", classification="pqc-safe",
            message="PQC via BouncyCastle", file="src/S.java", line=4),
]


# --------------------------------------------------------------------------
def test_score_is_pass_ratio():
    assert score(FINDINGS) == 33
    assert score([]) == 100
    assert score([finding(action="pass")]) == 100


def test_cbom_shape_is_cyclonedx_1_6():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert len(doc["components"]) == 3
    assert doc["components"][0]["type"] == "cryptographic-asset"
    assert doc["metadata"]["counts"] == {"block": 1, "warn": 1, "pass": 1}
    assert doc["metadata"]["score"] == 33


def test_cbom_content_hash_verifies():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    assert doc["metadata"]["contentHash"].startswith("sha384:")
    assert verify_cbom(doc)


def test_cbom_tampering_is_detected():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    doc["components"][0]["cryptoProperties"]["action"] = "pass"
    assert not verify_cbom(doc)


def test_content_hash_is_key_order_independent():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    reordered = json.loads(json.dumps(doc, sort_keys=True))
    assert content_hash(reordered) == content_hash(doc)


def test_cbom_paths_use_forward_slashes():
    doc = build_cbom([finding(file="app" + os.sep + "keys.py")], ".", "cnsa-2.0")
    assert "\\" not in doc["components"][0]["evidence"]["occurrences"][0]["location"]


def test_cbom_carries_exception_register():
    register = [{"policy": "no-new-rsa", "paths": ["legacy/**"], "reason": "SEC-142",
                 "expires": "2027-06-30", "days_left": 316, "expired": False}]
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0", exceptions=register)
    assert doc["metadata"]["exceptions"] == register


# --------------------------------------------------------------------------
@pytest.mark.skipif(not os.path.exists(SARIF_SCHEMA), reason="SARIF schema not vendored")
def test_sarif_validates_against_schema():
    with open(SARIF_SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.validate(build_sarif(FINDINGS, "."), schema)


def test_sarif_levels_map_from_actions():
    doc = build_sarif(FINDINGS, ".")
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_rule_metadata_is_deduped():
    doc = build_sarif(FINDINGS + [finding()], ".")
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids)) == 3


def test_sarif_locations_are_repo_relative(tmp_path):
    root = str(tmp_path)
    f = finding(file=os.path.join(root, "app", "keys.py"))
    doc = build_sarif([f], root)
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "app/keys.py"


def test_sarif_start_line_never_zero():
    doc = build_sarif([finding(line=0)], ".")
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_fingerprints_are_stable():
    a = build_sarif(FINDINGS, ".")["runs"][0]["results"][0]["partialFingerprints"]
    b = build_sarif(FINDINGS, ".")["runs"][0]["results"][0]["partialFingerprints"]
    assert a == b


# --------------------------------------------------------------------------
def test_cbom_delta_detects_added_and_removed():
    old = build_cbom(FINDINGS[:2], ".", "cnsa-2.0")
    new = build_cbom(FINDINGS[1:], ".", "cnsa-2.0")
    delta = cbom_delta(old, new)
    assert [a["rule"] for a in delta["added"]] == ["java-pqc-bc"]
    assert [r["rule"] for r in delta["removed"]] == ["py-rsa-keygen"]
    assert delta["score_from"] == 0 and delta["score_to"] == 50


def test_cbom_delta_empty_when_identical():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    delta = cbom_delta(doc, copy.deepcopy(doc))
    assert delta["added"] == [] and delta["removed"] == []
    assert markdown_diff(delta) == "No cryptographic changes."


def test_markdown_diff_renders_a_table():
    old = build_cbom(FINDINGS[:1], ".", "cnsa-2.0")
    new = build_cbom(FINDINGS, ".", "cnsa-2.0")
    md = markdown_diff(cbom_delta(old, new))
    assert md.startswith("| | Asset | Location | Classification |")
    assert "py-pqc-oqs" in md


# --------------------------------------------------------------------------
def test_report_attestation_verifies():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    text, attestation = readiness_report_markdown(doc, "Raven Defense Systems")
    ok, expected, found = verify_report(text)
    assert ok and found == attestation == expected


def test_report_tampering_is_detected():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Raven Defense Systems")
    tampered = text.replace("Blocking violations | 1", "Blocking violations | 0")
    assert not verify_report(tampered)[0]


def test_report_contains_control_mapping_and_hashes():
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Raven Defense Systems")
    assert "SC-13" in text and "SA-11" in text and "CM-3" in text
    assert doc["metadata"]["contentHash"] in text
    assert "Raven Defense Systems" in text


def test_report_exception_register_section():
    register = [{"policy": "no-new-rsa", "paths": ["legacy/**"], "reason": "SEC-142",
                 "expires": "2025-01-01", "days_left": -595, "expired": True}]
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0", exceptions=register)
    text, _ = readiness_report_markdown(doc, "Org")
    assert "SEC-142" in text and "EXPIRED" in text


def test_report_handles_clean_repo():
    doc = build_cbom([], ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Org")
    assert "100/100" in text
    assert verify_report(text)[0]


def test_pdf_renders(tmp_path):
    pytest.importorskip("reportlab")
    from pqgate.pdf import render_pdf
    doc = build_cbom(FINDINGS, ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Raven Defense Systems")
    out = tmp_path / "r.pdf"
    render_pdf(text, str(out), org="Raven Defense Systems")
    assert out.stat().st_size > 2000
    assert out.read_bytes().startswith(b"%PDF")


def test_cbom_locations_are_repo_relative(tmp_path):
    """Absolute paths would make every CI runner's CBOM diff against every other one."""
    root = str(tmp_path)
    f = finding(file=os.path.join(root, "auth", "keys.py"))
    doc = build_cbom([f], root, "cnsa-2.0")
    assert doc["components"][0]["evidence"]["occurrences"][0]["location"] == "auth/keys.py"


def test_cbom_diff_is_stable_across_checkout_paths(tmp_path):
    """Same code, two different runner working directories -> no spurious changes."""
    a, b = str(tmp_path / "runner-1"), str(tmp_path / "runner-2")
    old = build_cbom([finding(file=os.path.join(a, "auth", "keys.py"))], a, "cnsa-2.0")
    new = build_cbom([finding(file=os.path.join(b, "auth", "keys.py"))], b, "cnsa-2.0")
    delta = cbom_delta(old, new)
    assert delta["added"] == [] and delta["removed"] == []


# --------------------------------------------------------------------------
# SC-12 control coverage
# --------------------------------------------------------------------------
def sc12_finding(**kw):
    base = finding(action="block", rule="py-keygen-weak-rbg",
                   classification="keygen-not-approved",
                   message="Key material from a non-approved RBG",
                   file="app/keys.py", line=5)
    base["controls"] = ["SC-12", "SC-13"]
    base["standards"] = ["SP 800-133", "SP 800-90A"]
    base["remediation"] = "Use secrets.token_bytes()."
    base.update(kw)
    return base


def test_cbom_carries_controls_and_standards():
    doc = build_cbom([sc12_finding()], ".", "cnsa-2.0")
    props = doc["components"][0]["cryptoProperties"]
    assert props["controls"] == ["SC-12", "SC-13"]
    assert props["standards"] == ["SP 800-133", "SP 800-90A"]
    assert props["remediation"]


def test_sarif_tags_and_help_carry_the_control_axis():
    doc = build_sarif([sc12_finding()], ".")
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "SC-12" in rule["properties"]["tags"]
    assert rule["properties"]["controls"] == ["SC-12", "SC-13"]
    assert rule["help"]["text"] == "Use secrets.token_bytes()."


@pytest.mark.skipif(not os.path.exists(SARIF_SCHEMA), reason="SARIF schema not vendored")
def test_sarif_with_controls_still_validates():
    with open(SARIF_SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.validate(build_sarif([sc12_finding()] + FINDINGS, "."), schema)


def test_control_index_groups_by_control():
    from pqgate.outputs import control_index
    doc = build_cbom([sc12_finding(), finding()], ".", "cnsa-2.0")
    index = control_index(doc["components"])
    assert index["SC-12"]["total"] == 1
    assert index["SC-12"]["block"] == 1
    assert "SP 800-133" in index["SC-12"]["standards"]
    assert index["SC-13"]["total"] == 2, "findings with no controls default to SC-13"


def test_report_has_a_control_coverage_table():
    doc = build_cbom([sc12_finding(), finding()], ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Raven Defense Systems")
    assert "## NIST SP 800-53 Control Coverage" in text
    assert "| **SC-12** | Cryptographic Key Establishment and Management |" in text
    assert "### SC-12 — Cryptographic Key Establishment and Management" in text
    assert "SP 800-133" in text


def test_report_control_section_lists_failing_assets_only():
    doc = build_cbom([sc12_finding(), sc12_finding(action="pass", file="app/ok.py")],
                     ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Org")
    assert "app/keys.py:5" in text
    assert "app/ok.py" not in text.split("## Blocking Violations")[0]


def test_report_with_controls_still_attests():
    doc = build_cbom([sc12_finding()], ".", "cnsa-2.0")
    text, _ = readiness_report_markdown(doc, "Org")
    assert verify_report(text)[0]


def test_release_tarball_audit_rejects_private_files(tmp_path):
    """The release audit is the second lock on the export allowlist.

    A release is the one artifact that cannot be recalled, and release.py builds from
    whichever tree it is run in - including the private one, where docs/ holds the
    roadmap and CLAUDE.md holds internal context. The allowlist decides what goes in;
    this check refuses to publish if anything private got in anyway.
    """
    import importlib.util
    import os
    import tarfile

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "release_script", os.path.join(root, "scripts", "release.py"))
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)

    def build(members):
        path = tmp_path / "t.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name in members:
                f = tmp_path / "payload"
                f.write_text("x")
                tar.add(f, arcname="pqgate-0.0.0/" + name)
        return str(path)

    assert release.audit_tarball(build(["pqgate/cli.py", "README.md"])) == []
    for private in ("CLAUDE.md", "docs/release-roadmap.md", "server/app.py",
                    "scripts/seed.py", ".pqgate-keys/evidence.key"):
        leaked = release.audit_tarball(build(["pqgate/cli.py", private]))
        assert leaked == [private], private
