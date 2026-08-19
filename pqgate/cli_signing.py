"""CLI commands for evidence signing: `keys`, `sign`, and the signature half of `verify`."""
import json
import os
import sys

from . import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS
from .signing import (BackendUnavailable, SigningError, check_signer_allowed,
                      get_signer, registry)
from .signing import envelope, keystore


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _err(msg):
    print("pqgate: error: " + str(msg), file=sys.stderr)
    return EXIT_ERROR


# --------------------------------------------------------------------------
def cmd_keys(args):
    if args.action == "backends":
        print("")
        print("BACKEND".ljust(16) + "VALIDATED".ljust(11) + "AUDITED".ljust(9) + "STATUS")
        print("-" * 78)
        for name, backend in sorted(registry().items()):
            status = "available" if backend.available() else backend.unavailable_reason()
            print(name.ljust(16) + ("yes" if backend.validated else "no").ljust(11) +
                  ("yes" if backend.audited else "no").ljust(9) + status[:44])
            print(" " * 36 + backend.description)
        print("")
        return EXIT_PASS

    if args.action == "generate":
        try:
            signer = get_signer(args.signer)
        except (SigningError, BackendUnavailable) as exc:
            return _err(exc)
        try:
            info = keystore.generate(signer, args.dir, force=args.force)
        except keystore.KeystoreError as exc:
            return _err(exc)
        print("")
        print(signer.algorithm + " evidence keypair (" + signer.id + ")")
        print("  public   " + info["public_path"] + "  (" + str(info["public_bytes"]) + " bytes)")
        print("  private  " + info["private_path"] + "  (" + str(info["private_bytes"]) + " bytes)")
        print("  key id   " + info["fingerprint"])
        print("")
        if not signer.validated:
            print("  NOTE  " + signer.id + " is not a CMVP-validated cryptographic module" +
                  ("" if signer.audited else ", and is not an audited implementation") + ".")
        print("  NOTE  " + keystore.DEV_WARNING)
        print("")
        print("  Pin it so others can verify against it rather than against whatever key")
        print("  a document happens to carry:")
        print("      pqgate keys trust " + info["public_path"] + " --name 'Release Engineering'")
        print("")
        return EXIT_PASS

    if args.action == "trust":
        if not args.file:
            return _err("pqgate keys trust <evidence.pub> --name '...'")
        fp, path = keystore.trust(args.file, args.name or "unnamed")
        print("pinned " + keystore.short(fp) + " as '" + (args.name or "unnamed") + "' in " + path)
        return EXIT_PASS

    # list
    keys = keystore.load_trust()
    if args.json:
        print(json.dumps(keys, indent=2))
        return EXIT_PASS
    if not keys:
        print("no trusted keys pinned. Signatures will verify as 'valid-unpinned',")
        print("which proves the document was signed but not by whom.")
        return EXIT_PASS
    print("")
    print("FINGERPRINT".ljust(30) + "ADDED".ljust(13) + "NAME")
    print("-" * 78)
    for fp, meta in sorted(keys.items(), key=lambda kv: kv[1].get("name", "")):
        print(keystore.short(fp).ljust(30) + str(meta.get("added", "")).ljust(13) +
              str(meta.get("name", "")))
    print("")
    return EXIT_PASS


# --------------------------------------------------------------------------
def sign_file(path, signer_name=None, key_dir=None, profile=None,
              allow_unvalidated=False, quiet=False):
    """Sign a CBOM in place. Shared by `pqgate sign` and `scan --sign`."""
    signer = get_signer(signer_name)
    note = check_signer_allowed(signer, profile, allow_unvalidated)
    notes = [note] if note else []
    private_key, public_key = keystore.load(key_dir)
    doc = _load(path)
    envelope.sign_document(doc, signer, private_key, public_key, notes=notes)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    block = doc["metadata"]["signature"]
    if not quiet:
        print(" SIGN  -> " + path + "  " + block["algorithm"] + " via " + signer.id +
              "  key " + keystore.short(block["keyFingerprint"]))
        for n in notes:
            print("        NOTE " + n)
    return block


def cmd_sign(args):
    try:
        sign_file(args.file, args.signer, args.dir, profile=args.profile,
                  allow_unvalidated=args.allow_unvalidated_signer)
    except (SigningError, BackendUnavailable, keystore.KeystoreError) as exc:
        return _err(exc)
    except FileNotFoundError as exc:
        return _err(exc)
    return EXIT_PASS


# --------------------------------------------------------------------------
def describe_signature(doc, pubkey_path=None):
    """Render one line of signature status, and say whether it is acceptable."""
    pinned = None
    if pubkey_path:
        with open(pubkey_path, "rb") as fh:
            pinned = fh.read()
    result = envelope.verify_document(doc, pinned_public_key=pinned)
    status = result["status"]
    line = "signature: " + status + " - " + result["detail"]
    if result.get("trustedName"):
        line += " (" + result["trustedName"] + ")"
    extra = []
    if result.get("module") and not result.get("moduleValidated", False):
        extra.append("signing module '" + str(result["module"]) +
                     "' is not CMVP-validated")
    for n in result.get("notes") or []:
        extra.append(n)
    return status, line, extra
