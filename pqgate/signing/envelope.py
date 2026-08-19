"""The signature block: what gets signed, and what verification is allowed to claim.

Signed bytes are the canonical CBOM with `metadata.signature` removed and everything
else - including `metadata.contentHash` - left in place. So the signature covers the
content hash rather than competing with it: the hash proves the document is unaltered,
the signature proves who produced it.

`outputs.canonical` is reused rather than reimplemented, because two definitions of
"canonical bytes" in one codebase is a defect waiting to happen.
"""
import base64
import hashlib
import json

from ..outputs import canonical
from . import ALGORITHM, STANDARD
from .keystore import fingerprint, is_trusted

# Verification outcomes. Only VALID_PINNED means "we know who signed this".
VALID_PINNED = "valid-pinned"
VALID_UNPINNED = "valid-unpinned"
INVALID = "invalid"
UNSIGNED = "unsigned"
UNAVAILABLE = "unavailable"

OUTCOME_TEXT = {
    VALID_PINNED: "valid, signed by a trusted key",
    VALID_UNPINNED: "valid, but the key is not pinned - self-asserted, proves nothing about origin",
    INVALID: "INVALID - the signature does not verify",
    UNSIGNED: "unsigned",
    UNAVAILABLE: "cannot be checked - no backend for this algorithm",
}

ACCEPTABLE = (VALID_PINNED, VALID_UNPINNED)


def signed_bytes(doc):
    """Exact bytes covered by the signature."""
    stripped = json.loads(json.dumps(doc))
    stripped.get("metadata", {}).pop("signature", None)
    return canonical(stripped)


def sign_document(doc, signer, private_key, public_key, notes=None):
    """Attach a signature block. Returns the mutated document."""
    message = signed_bytes(doc)
    signature = signer.sign(private_key, message)
    block = {
        "algorithm": signer.algorithm,
        "standard": signer.standard,
        "value": base64.b64encode(signature).decode(),
        "publicKey": base64.b64encode(public_key).decode(),
        "keyFingerprint": fingerprint(public_key),
        "signedDigest": "sha384:" + hashlib.sha384(message).hexdigest(),
        # Beyond the usual fields: which module signed, and whether it is validated.
        # Without these, "signed" and "signed by a validated module" look identical.
        "module": signer.module_id,
        "moduleValidated": bool(signer.validated),
        "moduleAudited": bool(signer.audited),
        "signer": signer.id,
    }
    if notes:
        block["notes"] = list(notes)
    doc.setdefault("metadata", {})["signature"] = block
    return doc


def signature_block(doc):
    return (doc.get("metadata") or {}).get("signature")


def verify_document(doc, trust_path=None, pinned_public_key=None, signer=None):
    """Check a signature and report which of the five outcomes applies.

    An unpinned key is never reported as plain 'valid'. A document that carries its
    own public key proves only that whoever wrote it also held a private key - which
    is true of anyone who can run keygen.
    """
    block = signature_block(doc)
    if not block:
        return {"status": UNSIGNED, "detail": OUTCOME_TEXT[UNSIGNED]}

    if block.get("algorithm") != ALGORITHM:
        return {"status": UNAVAILABLE,
                "detail": "unsupported signature algorithm: " + str(block.get("algorithm")),
                "algorithm": block.get("algorithm")}

    if signer is None:
        from . import BackendUnavailable, get_signer
        try:
            signer = get_signer()
        except BackendUnavailable as exc:
            return {"status": UNAVAILABLE, "detail": str(exc).splitlines()[0]}

    embedded = base64.b64decode(block["publicKey"])
    public_key = pinned_public_key if pinned_public_key is not None else embedded
    fp = fingerprint(public_key)

    ok = signer.verify(public_key, signed_bytes(doc), base64.b64decode(block["value"]))
    if not ok:
        return {"status": INVALID, "detail": OUTCOME_TEXT[INVALID], "keyFingerprint": fp}

    pinned = pinned_public_key is not None or is_trusted(fp, trust_path)
    status = VALID_PINNED if pinned else VALID_UNPINNED
    trusted = is_trusted(fp, trust_path)
    return {
        "status": status,
        "detail": OUTCOME_TEXT[status],
        "keyFingerprint": fp,
        "trustedName": (load_name(fp, trust_path) if trusted else None),
        "module": block.get("module"),
        "moduleValidated": block.get("moduleValidated", False),
        "signer": block.get("signer"),
        "algorithm": block.get("algorithm"),
        "standard": block.get("standard", STANDARD),
        "notes": block.get("notes", []),
    }


def load_name(fp, trust_path=None):
    from .keystore import load_trust
    return (load_trust(trust_path).get(fp) or {}).get("name")
