"""Evidence signing: the crypto envelope, the trust model, and the profile guardrails.

The trust-model tests matter more than the round-trip ones. A signature scheme that
verifies correctly but reports "VALID" for a document an attacker re-signed is worse
than no signature at all, because it launders a forgery into an audit artifact.
"""
import base64
import json
import os

import pytest

from pqgate.outputs import build_cbom, content_hash, verify_cbom
from pqgate.signing import (BackendUnavailable, SigningError, check_signer_allowed,
                                get_signer, registry)
from pqgate.signing import envelope, keystore
from pqgate.signing.envelope import (INVALID, UNSIGNED, VALID_PINNED, VALID_UNPINNED,
                                         sign_document, signed_bytes, verify_document)

pytestmark = pytest.mark.skipif(
    not any(b.available() for b in registry().values()),
    reason="no ML-DSA-87 backend installed")


@pytest.fixture()
def signer():
    return get_signer()


@pytest.fixture()
def keys(signer):
    public_key, private_key = signer.keygen()
    return private_key, public_key


def finding(action="block", **kw):
    base = {"rule": "py-rsa-keygen", "classification": "quantum-vulnerable",
            "message": "RSA key generation", "file": "app/keys.py", "line": 5,
            "evidence": "rsa.generate_private_key(...)", "detector": "ast",
            "action": action, "policy_id": "no-new-rsa", "controls": ["SC-13"],
            "standards": [], "remediation": ""}
    base.update(kw)
    return base


def cbom():
    return build_cbom([finding()], ".", "cnsa-2.0")


# --------------------------------------------------------------------------
# Backend selection
# --------------------------------------------------------------------------
def test_backends_declare_validation_and_audit_status():
    for name, backend in registry().items():
        assert isinstance(backend.validated, bool), name
        assert isinstance(backend.audited, bool), name
        assert backend.module_id or name == "pkcs11"


def test_liboqs_probe_does_not_import_the_package():
    """`import oqs` clones and builds liboqs from GitHub when the native library is
    missing. Probing availability must never trigger that - it is a network call and
    it executes code fetched at runtime."""
    import sys
    from pqgate.signing.liboqs import LiboqsSigner
    sys.modules.pop("oqs", None)
    LiboqsSigner.available()
    assert "oqs" not in sys.modules, "probing availability must not import oqs"


def test_unknown_backend_is_an_error():
    with pytest.raises(SigningError):
        get_signer("does-not-exist")


def test_pkcs11_is_declared_but_not_implemented():
    from pqgate.signing.pkcs11 import Pkcs11Signer
    assert Pkcs11Signer.validated is True
    assert Pkcs11Signer.available() is False
    with pytest.raises(BackendUnavailable):
        get_signer("pkcs11")


# --------------------------------------------------------------------------
# Round trip
# --------------------------------------------------------------------------
def test_sign_and_verify_round_trip(signer, keys):
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    assert verify_document(doc)["status"] in (VALID_PINNED, VALID_UNPINNED)


def test_signature_block_records_the_module(signer, keys):
    private_key, public_key = keys
    block = sign_document(cbom(), signer, private_key, public_key)["metadata"]["signature"]
    assert block["algorithm"] == "ML-DSA-87"
    assert block["standard"] == "FIPS 204"
    assert block["module"] == signer.module_id
    assert block["moduleValidated"] is signer.validated
    assert block["keyFingerprint"].startswith("sha384:")


def test_unsigned_document_is_reported_as_such():
    assert verify_document(cbom())["status"] == UNSIGNED


def test_signing_does_not_invalidate_the_content_hash(signer, keys):
    """The hash covers the content; the signature is an envelope around it. If the
    hash also covered the signature the two would be circular."""
    private_key, public_key = keys
    doc = cbom()
    before = content_hash(doc)
    assert verify_cbom(doc)
    sign_document(doc, signer, private_key, public_key)
    assert content_hash(doc) == before
    assert verify_cbom(doc), "attaching a signature must not break the content hash"


def test_signature_covers_the_content_hash(signer, keys):
    """Editing the stored hash must break the signature, not just the hash check."""
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    doc["metadata"]["contentHash"] = "sha384:" + "0" * 96
    assert verify_document(doc)["status"] == INVALID


# --------------------------------------------------------------------------
# Tamper detection
# --------------------------------------------------------------------------
@pytest.mark.parametrize("mutate", [
    pytest.param(lambda d: d["components"][0]["cryptoProperties"].__setitem__("action", "pass"),
                 id="finding-action"),
    pytest.param(lambda d: d["metadata"].__setitem__("score", 100), id="score"),
    pytest.param(lambda d: d["components"].clear(), id="drop-all-findings"),
    pytest.param(lambda d: d["metadata"].__setitem__("profile", "nist-baseline"), id="profile"),
])
def test_tampering_invalidates_the_signature(signer, keys, mutate):
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    mutate(doc)
    assert verify_document(doc)["status"] == INVALID


def test_truncated_signature_is_invalid(signer, keys):
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    raw = base64.b64decode(doc["metadata"]["signature"]["value"])
    doc["metadata"]["signature"]["value"] = base64.b64encode(raw[:-1]).decode()
    assert verify_document(doc)["status"] == INVALID


# --------------------------------------------------------------------------
# The trust model - the part that actually matters
# --------------------------------------------------------------------------
def test_embedded_key_alone_is_never_reported_as_trusted(tmp_path, signer, keys):
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    result = verify_document(doc, trust_path=str(tmp_path / "trust.yml"))
    assert result["status"] == VALID_UNPINNED
    assert "self-asserted" in result["detail"]


def test_attacker_can_re_sign_but_cannot_become_pinned(tmp_path, signer, keys):
    """The whole point of the trust store. An attacker who edits a CBOM and re-signs
    it with their own key produces a cryptographically valid signature - and must
    still be distinguishable from the real signer."""
    private_key, public_key = keys
    trust_path = str(tmp_path / "trust.yml")
    pub_file = tmp_path / "evidence.pub"
    pub_file.write_bytes(public_key)
    keystore.trust(str(pub_file), "Release Engineering", path=trust_path)

    genuine = sign_document(cbom(), signer, private_key, public_key)
    assert verify_document(genuine, trust_path=trust_path)["status"] == VALID_PINNED

    forged = json.loads(json.dumps(genuine))
    forged["metadata"].pop("signature")
    forged["components"][0]["cryptoProperties"]["action"] = "pass"
    attacker_public, attacker_private = signer.keygen()
    sign_document(forged, signer, attacker_private, attacker_public)

    result = verify_document(forged, trust_path=trust_path)
    assert result["status"] == VALID_UNPINNED, "a forged document must not be 'pinned'"
    assert result["status"] != VALID_PINNED


def test_verifying_against_a_pinned_key_rejects_a_forgery(signer, keys):
    private_key, public_key = keys
    forged = cbom()
    attacker_public, attacker_private = signer.keygen()
    sign_document(forged, signer, attacker_private, attacker_public)
    result = verify_document(forged, pinned_public_key=public_key)
    assert result["status"] == INVALID


def test_trust_store_round_trip(tmp_path, keys):
    _, public_key = keys
    pub_file = tmp_path / "evidence.pub"
    pub_file.write_bytes(public_key)
    path = str(tmp_path / "trust.yml")
    fp, written = keystore.trust(str(pub_file), "Raven Release Engineering", path=path)
    assert written == path
    assert keystore.is_trusted(fp, path)
    assert keystore.load_trust(path)[fp]["name"] == "Raven Release Engineering"


# --------------------------------------------------------------------------
# Profile guardrails
# --------------------------------------------------------------------------
def test_fips_profile_refuses_an_unvalidated_signer(signer):
    if signer.validated:
        pytest.skip("selected backend is validated")
    with pytest.raises(SigningError, match="CMVP-validated"):
        check_signer_allowed(signer, "fips-140-3")
    with pytest.raises(SigningError):
        check_signer_allowed(signer, "cnsa-2.0-fips")


def test_unvalidated_signer_allowed_with_an_explicit_flag(signer):
    if signer.validated:
        pytest.skip("selected backend is validated")
    note = check_signer_allowed(signer, "fips-140-3", allow_unvalidated=True)
    assert note and "not a CMVP-validated module" in note


def test_non_fips_profiles_do_not_require_a_validated_signer(signer):
    assert check_signer_allowed(signer, "cnsa-2.0") is None
    assert check_signer_allowed(signer, None) is None


def test_override_is_recorded_in_the_signature(signer, keys):
    if signer.validated:
        pytest.skip("selected backend is validated")
    private_key, public_key = keys
    note = check_signer_allowed(signer, "fips-140-3", allow_unvalidated=True)
    doc = sign_document(cbom(), signer, private_key, public_key, notes=[note])
    assert doc["metadata"]["signature"]["notes"] == [note]


# --------------------------------------------------------------------------
# Keystore
# --------------------------------------------------------------------------
def test_dev_private_key_is_named_insecure(tmp_path, signer):
    info = keystore.generate(signer, str(tmp_path))
    assert "INSECURE-DEV" in os.path.basename(info["private_path"])
    assert os.path.exists(info["public_path"])


def test_keystore_refuses_to_overwrite_without_force(tmp_path, signer):
    keystore.generate(signer, str(tmp_path))
    with pytest.raises(keystore.KeystoreError, match="refusing to overwrite"):
        keystore.generate(signer, str(tmp_path))
    keystore.generate(signer, str(tmp_path), force=True)


def test_keystore_load_reports_a_missing_key_clearly(tmp_path):
    with pytest.raises(keystore.KeystoreError, match="no signing key"):
        keystore.load(str(tmp_path))


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
def test_report_states_the_signing_module_and_its_status(signer, keys):
    from pqgate.outputs import readiness_report_markdown, verify_report
    private_key, public_key = keys
    doc = sign_document(cbom(), signer, private_key, public_key)
    text, _ = readiness_report_markdown(doc, "Raven Defense Systems")
    assert "Evidence signature" in text
    assert "ML-DSA-87" in text
    assert ("Module CMVP-validated | **no**" in text) is (not signer.validated)
    assert verify_report(text)[0], "the signature section must sit inside the attestation"


def test_unsigned_report_says_so():
    from pqgate.outputs import readiness_report_markdown
    text, _ = readiness_report_markdown(cbom(), "Org")
    assert "Evidence signature: none" in text
    assert "integrity" in text and "authenticity" in text


def test_signed_bytes_exclude_only_the_signature(signer, keys):
    private_key, public_key = keys
    doc = cbom()
    before = signed_bytes(doc)
    sign_document(doc, signer, private_key, public_key)
    assert signed_bytes(doc) == before
    assert b"contentHash" in before, "the signature must cover the content hash"


# --------------------------------------------------------------------------
# We hold ourselves to the same rule
# --------------------------------------------------------------------------
def test_our_own_signing_backend_is_flagged(tmp_path):
    """PQgate ships an unaudited signing backend for development. If our own
    scanner cannot see that, the rule is worthless."""
    from pqgate.profiles import get_profile
    from pqgate.scanner import scan_tree
    (tmp_path / "signer.py").write_text(
        "from dilithium_py.ml_dsa import ML_DSA_87\n", encoding="utf-8")
    hits = [f for f in scan_tree(str(tmp_path), get_profile("cnsa-2.0"))
            if f["rule"] == "py-unaudited-pqc-impl"]
    assert len(hits) == 1
    assert "IA-7" in hits[0]["controls"]


def test_unaudited_backend_blocks_under_fips(tmp_path):
    from pqgate.policy import apply_policy, load_policy
    from pqgate.profiles import get_profile
    from pqgate.scanner import scan_tree
    (tmp_path / "signer.py").write_text(
        "from dilithium_py.ml_dsa import ML_DSA_87\n", encoding="utf-8")
    findings = scan_tree(str(tmp_path), get_profile("fips-140-3"))
    kept, _ = apply_policy(findings, load_policy(None, profile_override="fips-140-3"))
    assert kept[0]["action"] == "block"
