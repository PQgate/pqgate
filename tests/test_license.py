"""Licensing, rule-pack staleness and signed pack bundles.

The single most important property in this file: scanning never consults a license.
If that ever stops being true, the free tier becomes crippleware and the distribution
model stops working. `test_scanning_never_touches_the_license` is the guard.
"""
import base64
import datetime
import json
import os
import tarfile

import pytest

from pqgate import EXIT_ERROR, EXIT_PASS
from pqgate.cli import main
from pqgate.license import (ALWAYS_FREE, ENTITLEMENTS, License, LicenseError,
                                load_license, require, signing_payload, verify_license)
from pqgate.rules import ALL_PACKS, STALE_AFTER_DAYS, pack_metadata, stale_packs

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEMO = os.path.join(ROOT, "demo-repo")


def run(*argv):
    return main(["--no-color", *argv])


def _have_signer():
    from pqgate.signing import registry
    return any(b.available() for b in registry().values())


def make_license(days=365, entitlements=("rules:update",), org="Raven Defense Systems"):
    return {
        "org": org,
        "tier": "enterprise",
        "issued": datetime.date.today().isoformat(),
        "expires": (datetime.date.today() + datetime.timedelta(days=days)).isoformat(),
        "entitlements": list(entitlements),
    }


def sign_license(doc, signer, private_key):
    doc = dict(doc)
    doc["signature"] = base64.b64encode(signer.sign(private_key, signing_payload(doc))).decode()
    return doc


# --------------------------------------------------------------------------
# The line that must not move
# --------------------------------------------------------------------------
def test_scanning_never_touches_the_license(monkeypatch, capsys):
    """A scan must not read, verify or care about a license. Ever."""
    import pqgate.license as lic

    def explode(*_a, **_k):
        raise AssertionError("the scan path consulted the license")

    monkeypatch.setattr(lic, "load_license", explode)
    monkeypatch.setattr(lic, "require", explode)
    monkeypatch.setattr(lic, "find_license", explode)
    assert run("scan", DEMO, "--fail-on", "never") == EXIT_PASS
    assert "GATE" in capsys.readouterr().out


def test_free_list_covers_the_scan_path():
    joined = " ".join(ALWAYS_FREE).lower()
    for capability in ("scanning", "cbom", "verification", "profiles"):
        assert capability in joined, capability + " must be listed as always free"


def test_entitlements_are_only_about_updates():
    """Nothing an entitlement gates may be part of producing a scan."""
    for name in ENTITLEMENTS:
        assert name.split(":")[0] in ("rules", "cmvp", "profiles", "evidence", "support")
        assert not name.startswith("scan")


# --------------------------------------------------------------------------
# License documents
# --------------------------------------------------------------------------
def test_missing_license_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    license_ = load_license()
    assert license_.status() == "none"
    assert not license_.grants("rules:update")
    assert "free" in license_.describe()


def test_unsigned_license_grants_nothing(tmp_path):
    path = tmp_path / "license.json"
    path.write_text(json.dumps(make_license()), encoding="utf-8")
    license_ = load_license(str(path))
    assert license_.status() == "unverified"
    assert not license_.grants("rules:update")


@pytest.mark.skipif(not _have_signer(), reason="no ML-DSA-87 backend installed")
def test_signed_license_verifies_offline():
    from pqgate.signing import get_signer
    signer = get_signer()
    public_key, private_key = signer.keygen()
    doc = sign_license(make_license(), signer, private_key)
    license_ = verify_license(doc, base64.b64encode(public_key).decode())
    assert license_.verified and license_.status() == "active"
    assert license_.grants("rules:update")
    assert not license_.grants("evidence:api")


@pytest.mark.skipif(not _have_signer(), reason="no ML-DSA-87 backend installed")
def test_tampered_license_does_not_verify():
    from pqgate.signing import get_signer
    signer = get_signer()
    public_key, private_key = signer.keygen()
    doc = sign_license(make_license(entitlements=["rules:update"]), signer, private_key)
    doc["entitlements"].append("evidence:api")
    license_ = verify_license(doc, base64.b64encode(public_key).decode())
    assert not license_.verified
    assert not license_.grants("evidence:api")


@pytest.mark.skipif(not _have_signer(), reason="no ML-DSA-87 backend installed")
def test_expired_license_grants_nothing():
    from pqgate.signing import get_signer
    signer = get_signer()
    public_key, private_key = signer.keygen()
    doc = sign_license(make_license(days=-1), signer, private_key)
    license_ = verify_license(doc, base64.b64encode(public_key).decode())
    assert license_.verified and license_.expired()
    assert license_.status() == "expired"
    assert not license_.grants("rules:update")
    assert "keep working" in license_.describe()


def test_no_bundled_key_says_so_rather_than_pretending():
    """A build with no license-signing key must not silently accept or reject."""
    license_ = verify_license({"org": "x", "signature": "AA=="}, "")
    assert not license_.verified
    assert "no license-signing public key" in license_.reason


def test_require_raises_without_an_entitlement(tmp_path, monkeypatch):
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    with pytest.raises(LicenseError, match="rules:update"):
        require("rules:update")


def test_require_message_reassures_about_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    try:
        require("rules:update")
    except LicenseError as exc:
        assert "Scanning is unaffected" in str(exc)


# --------------------------------------------------------------------------
# Rule pack staleness
# --------------------------------------------------------------------------
def test_every_pack_declares_a_release_date():
    packs = {p["name"]: p for p in pack_metadata()}
    assert len(packs) == len(ALL_PACKS)
    for name, pack in packs.items():
        assert pack["released"], name + " has no release date"
        assert pack["description"], name + " has no description"


def test_fresh_packs_are_not_stale():
    assert stale_packs() == [], "packs shipped in this build should be current"


def test_stale_detection_uses_the_threshold(monkeypatch):
    import pqgate.rules as rules
    old = (datetime.date.today() - datetime.timedelta(days=STALE_AFTER_DAYS + 5)).isoformat()
    real = rules._read_pack

    def aged(path):
        doc = real(path)
        if isinstance(doc, dict) and doc.get("pack"):
            doc["pack"] = dict(doc["pack"], released=old)
        return doc

    monkeypatch.setattr(rules, "_read_pack", aged)
    stale = rules.stale_packs()
    assert len(stale) == len(ALL_PACKS)
    assert all(p["age_days"] > STALE_AFTER_DAYS for p in stale)


def test_stale_packs_add_a_scan_note_but_not_a_failure(monkeypatch, capsys):
    """A stale pack is reported. It never changes the verdict."""
    import pqgate.rules as rules
    old = (datetime.date.today() - datetime.timedelta(days=STALE_AFTER_DAYS + 5)).isoformat()
    real = rules._read_pack

    def aged(path):
        doc = real(path)
        if isinstance(doc, dict) and doc.get("pack"):
            doc["pack"] = dict(doc["pack"], released=old)
        return doc

    monkeypatch.setattr(rules, "_read_pack", aged)
    code = run("scan", DEMO, "--fail-on", "never")
    out = capsys.readouterr().out
    assert code == EXIT_PASS
    assert "days old" in out and "pqgate packs" in out


# --------------------------------------------------------------------------
# Signed rule pack bundles
# --------------------------------------------------------------------------
@pytest.mark.skipif(not _have_signer(), reason="no ML-DSA-87 backend installed")
def test_pack_bundle_round_trip(tmp_path, monkeypatch, capsys):
    from pqgate.cli_license import verify_bundle
    from pqgate.signing import get_signer
    from pqgate.signing.keystore import generate

    key_dir = tmp_path / "keys"
    generate(get_signer(), str(key_dir))
    bundle = tmp_path / "packs.tar.gz"
    assert run("packs-build", "2026.09.1", "--out", str(bundle),
               "--key-dir", str(key_dir)) == EXIT_PASS
    capsys.readouterr()

    manifest, contents, notes = verify_bundle(str(bundle))
    assert manifest["version"] == "2026.09.1"
    assert set(contents) == set(manifest["files"])
    assert manifest["signature"]["algorithm"] == "ML-DSA-87"
    assert any("not a CMVP-validated module" in n for n in notes)


def test_unsigned_bundle_is_flagged(tmp_path, capsys):
    from pqgate.cli_license import verify_bundle
    bundle = tmp_path / "packs.tar.gz"
    assert run("packs-build", "2026.09.1", "--out", str(bundle), "--unsigned") == EXIT_PASS
    capsys.readouterr()
    _manifest, _contents, notes = verify_bundle(str(bundle))
    assert any("UNSIGNED" in n for n in notes)


@pytest.mark.skipif(not _have_signer(), reason="no ML-DSA-87 backend installed")
def test_tampered_bundle_is_refused(tmp_path, capsys):
    from pqgate.cli_license import BUNDLE_MANIFEST, verify_bundle
    from pqgate.signing import get_signer
    from pqgate.signing.keystore import generate

    key_dir = tmp_path / "keys"
    generate(get_signer(), str(key_dir))
    bundle = tmp_path / "packs.tar.gz"
    run("packs-build", "2026.09.1", "--out", str(bundle), "--key-dir", str(key_dir))
    capsys.readouterr()

    # Repack with one rule file altered; the manifest digest no longer matches.
    work = tmp_path / "work"
    work.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
        tar.extractall(work)
    target = work / "source.yml"
    target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(tampered, "w:gz") as tar:
        for name in sorted(os.listdir(work)):
            tar.add(work / name, arcname=name)

    with pytest.raises(LicenseError, match="digest mismatch"):
        verify_bundle(str(tampered))
    assert os.path.exists(work / BUNDLE_MANIFEST)


def test_bundle_update_requires_an_entitlement(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    bundle = tmp_path / "packs.tar.gz"
    run("packs-build", "2026.09.1", "--out", str(bundle), "--unsigned")
    capsys.readouterr()
    assert run("packs-update", str(bundle)) == EXIT_ERROR


def test_dry_run_needs_no_license(tmp_path, monkeypatch, capsys):
    """Anyone handed a bundle can inspect it. Inspecting is not installing."""
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    bundle = tmp_path / "packs.tar.gz"
    run("packs-build", "2026.09.1", "--out", str(bundle), "--unsigned")
    capsys.readouterr()
    assert run("packs-update", str(bundle), "--dry-run") == EXIT_PASS
    assert "would install" in capsys.readouterr().out


# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------
def test_license_command_lists_what_is_free(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("pqgate.license.LICENSE_PATHS", (str(tmp_path / "nope.json"),))
    monkeypatch.delenv("PQGATE_LICENSE", raising=False)
    assert run("license") == EXIT_PASS
    out = capsys.readouterr().out
    assert "FREE, ALWAYS" in out
    assert "no license required or checked" in out


def test_packs_command_reports_age(capsys):
    assert run("packs") == EXIT_PASS
    out = capsys.readouterr().out
    assert "PACK" in out and "RELEASED" in out
    assert "stale after " + str(STALE_AFTER_DAYS) in out


def test_license_install_round_trip(tmp_path, capsys):
    src = tmp_path / "license.json"
    src.write_text(json.dumps(make_license()), encoding="utf-8")
    target = tmp_path / "installed.json"
    assert run("license", "install", str(src), "--out", str(target)) == EXIT_PASS
    assert json.loads(target.read_text(encoding="utf-8"))["org"] == "Raven Defense Systems"
    assert "installed" in capsys.readouterr().out
