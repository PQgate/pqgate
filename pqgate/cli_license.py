"""CLI for licensing and rule-pack updates.

The whole subscription rests on one honest fact: rule packs go stale. Guidance moves,
libraries change, new parameter sets appear, and a pack from last year quietly reports
clean on code it should flag. So the paid thing is the refresh, not the tool.

Nothing here is on the scan path. `pqgate scan` never consults a license.
"""
import base64
import hashlib
import json
import os
import shutil
import tarfile
import tempfile

from . import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS
# Imported as a module, not by value: these are the functions a test or an embedder
# most wants to substitute, and a from-import would freeze whatever was bound first.
from . import license as license_mod
from .license import ALWAYS_FREE, ENTITLEMENTS, LICENSE_PATHS, LicenseError
from .rules import ALL_PACKS, STALE_AFTER_DAYS, _HERE, pack_metadata, stale_packs

BUNDLE_MANIFEST = "pack-manifest.json"


def _err(msg):
    import sys
    print("pqgate: error: " + str(msg), file=sys.stderr)
    return EXIT_ERROR


# --------------------------------------------------------------------------
def cmd_license(args):
    if args.action == "install":
        if not args.file:
            return _err("pqgate license install <license.json>")
        try:
            with open(args.file, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            return _err(exc)
        checked = license_mod.verify_license(doc)
        if not checked.verified:
            print("WARNING: " + checked.reason)
            print("Installing anyway so an offline host can hold it, but entitlements")
            print("will not be granted until the signature verifies.")
        target = args.out or LICENSE_PATHS[0]
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        print("installed -> " + target)
        print("  " + checked.describe())
        return EXIT_PASS

    license_ = license_mod.load_license(args.file)
    if args.json:
        print(json.dumps({
            "status": license_.status(), "org": license_.org, "tier": license_.tier,
            "entitlements": list(license_.entitlements),
            "expires": str(license_.expires) if license_.expires else None,
            "days_left": license_.days_left(), "verified": license_.verified,
            "reason": license_.reason, "path": getattr(license_, "path", None),
        }, indent=2))
        return EXIT_PASS

    print("")
    print("LICENSE   " + license_.describe())
    if getattr(license_, "path", None):
        print("FILE      " + license_.path)
    print("")
    if license_.entitlements:
        print("ENTITLEMENTS")
        for e in license_.entitlements:
            granted = "granted" if license_.grants(e) else "not in effect"
            print("  " + e.ljust(20) + granted.ljust(16) + ENTITLEMENTS.get(e, ""))
        print("")
    print("FREE, ALWAYS - no license required or checked")
    for item in ALWAYS_FREE:
        print("  - " + item)
    print("")

    stale = stale_packs()
    if stale:
        print("RULE PACKS")
        for pack in stale:
            print("  " + pack["name"].ljust(12) + str(pack["age_days"]) +
                  " days old - stale")
        print("  Stale packs keep working. They also stop finding things.")
        print("  Update: pqgate rules update <bundle.tar.gz>")
        print("")
    return EXIT_PASS if license_.status() != "unverified" else EXIT_BLOCKED


# --------------------------------------------------------------------------
def cmd_packs(args):
    """Show installed rule packs and their age."""
    packs = pack_metadata()
    if args.json:
        print(json.dumps(packs, indent=2))
        return EXIT_PASS
    print("")
    print("PACK".ljust(12) + "RELEASED".ljust(13) + "AGE".rjust(6) + "  DESCRIPTION")
    print("-" * 78)
    for pack in packs:
        age = "-" if pack["age_days"] is None else (str(pack["age_days"]) + "d")
        flag = "  STALE" if pack["stale"] else ""
        print(pack["name"].ljust(12) + str(pack["released"] or "-").ljust(13) +
              age.rjust(6) + "  " + pack["description"] + flag)
    stale = [p for p in packs if p["stale"]]
    print("")
    if stale:
        print(str(len(stale)) + " pack(s) older than " + str(STALE_AFTER_DAYS) +
              " days. They keep working; they also stop finding things.")
    else:
        print("All packs current (stale after " + str(STALE_AFTER_DAYS) + " days).")
    print("")
    return EXIT_PASS


# --------------------------------------------------------------------------
def bundle_digest(path):
    with open(path, "rb") as fh:
        return "sha384:" + hashlib.sha384(fh.read()).hexdigest()


def cmd_packs_build(args):
    """Build a signed rule-pack bundle. Used by the release pipeline, not by customers."""
    from .signing import get_signer
    from .signing.keystore import load as load_key

    out = args.out or ("pqgate-rules-" + args.version + ".tar.gz")
    manifest = {
        "kind": "pqgate-rule-pack",
        "version": args.version,
        "packs": pack_metadata(),
        "files": {},
    }
    with tempfile.TemporaryDirectory() as staging:
        for name in ALL_PACKS:
            src = os.path.join(_HERE, name)
            if not os.path.exists(src):
                continue
            shutil.copy2(src, os.path.join(staging, name))
            with open(src, "rb") as fh:
                manifest["files"][name] = "sha384:" + hashlib.sha384(fh.read()).hexdigest()

        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        if not args.unsigned:
            signer = get_signer(args.signer)
            private_key, public_key = load_key(args.key_dir)
            manifest["signature"] = {
                "algorithm": signer.algorithm,
                "value": base64.b64encode(signer.sign(private_key, payload)).decode(),
                "publicKey": base64.b64encode(public_key).decode(),
                "module": signer.module_id,
                "moduleValidated": bool(signer.validated),
            }
        with open(os.path.join(staging, BUNDLE_MANIFEST), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        with tarfile.open(out, "w:gz") as tar:
            for name in sorted(os.listdir(staging)):
                tar.add(os.path.join(staging, name), arcname=name)

    digest = bundle_digest(out)
    with open(out + ".sha384", "w", encoding="utf-8") as fh:
        fh.write(digest + "  " + os.path.basename(out) + "\n")
    print("rule pack bundle -> " + out)
    print("  " + digest)
    print("  " + str(len(manifest["files"])) + " packs" +
          ("" if args.unsigned else ", signed with " + manifest["signature"]["algorithm"]))
    return EXIT_PASS


def _read_bundle(path):
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or "/" in member.name or member.name.startswith(".."):
                raise LicenseError("bundle contains an unexpected entry: " + member.name)
        manifest_member = tar.extractfile(BUNDLE_MANIFEST)
        if manifest_member is None:
            raise LicenseError("bundle has no " + BUNDLE_MANIFEST)
        manifest = json.loads(manifest_member.read().decode("utf-8"))
        contents = {m.name: tar.extractfile(m).read() for m in tar.getmembers()
                    if m.isfile() and m.name != BUNDLE_MANIFEST}
    return manifest, contents


def verify_bundle(path):
    """Check a bundle's signature and per-file digests. Returns (manifest, contents, notes)."""
    manifest, contents = _read_bundle(path)
    notes = []
    if manifest.get("kind") != "pqgate-rule-pack":
        raise LicenseError("not a PQgate rule pack bundle")

    for name, digest in (manifest.get("files") or {}).items():
        blob = contents.get(name)
        if blob is None:
            raise LicenseError("bundle is missing a file listed in its manifest: " + name)
        actual = "sha384:" + hashlib.sha384(blob).hexdigest()
        if actual != digest:
            raise LicenseError("digest mismatch for " + name + " - refusing to install")

    signature = manifest.get("signature")
    if not signature:
        notes.append("bundle is UNSIGNED - install it only if you produced it yourself")
        return manifest, contents, notes

    from .signing import get_signer
    payload = json.dumps({k: v for k, v in manifest.items() if k != "signature"},
                         sort_keys=True, separators=(",", ":")).encode()
    signer = get_signer()
    ok = signer.verify(base64.b64decode(signature["publicKey"]), payload,
                       base64.b64decode(signature["value"]))
    if not ok:
        raise LicenseError("bundle signature does not verify - refusing to install")
    if not signature.get("moduleValidated", False):
        notes.append("bundle was signed by '" + str(signature.get("module")) +
                     "', which is not a CMVP-validated module")
    return manifest, contents, notes


def cmd_packs_update(args):
    """Install a signed rule-pack bundle. This is the entitled action."""
    try:
        # Inspecting a bundle is not installing one. --dry-run always works, so anyone
        # handed a bundle can see what is in it before deciding anything.
        if not args.no_license_check and not args.dry_run:
            license_ = license_mod.require("rules:update")
            print("license: " + license_.describe())
        manifest, contents, notes = verify_bundle(args.bundle)
    except (LicenseError, OSError, tarfile.TarError) as exc:
        return _err(exc)

    for note in notes:
        print("NOTE " + note)
    if args.dry_run:
        print("\nwould install " + str(len(contents)) + " packs from version " +
              str(manifest.get("version")) + ":")
        for pack in manifest.get("packs", []):
            print("  " + pack["name"].ljust(12) + str(pack.get("released")))
        return EXIT_PASS

    for name, blob in contents.items():
        with open(os.path.join(_HERE, name), "wb") as fh:
            fh.write(blob)
    print("installed rule pack version " + str(manifest.get("version")) +
          " (" + str(len(contents)) + " packs)")
    for pack in pack_metadata():
        print("  " + pack["name"].ljust(12) + str(pack["released"]))
    return EXIT_PASS
