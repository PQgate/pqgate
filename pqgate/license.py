"""Licensing.

The line this file draws, and it is deliberate:

    SCANNING NEVER REQUIRES A LICENSE.

Discovery is free, permanently, for anyone. A license gates *updates* — newer rule
packs and refreshed CMVP certificate data — not the act of scanning. That is the honest
version of the subscription argument: the packs you downloaded keep working forever, and
they go stale, because the guidance underneath them moves.

Crippling the scanner would be both wrong and self-defeating. The scanner is the
distribution channel; someone who runs it and finds five blocking violations is already
integrated. What they cannot reproduce is a rule pack that is current next quarter.

A license is a JSON document signed with ML-DSA-87 by the PQgate license key, and
verified offline against the public key bundled below. Offline verification is not a
convenience here — an air-gapped customer must be able to prove entitlement on a machine
that will never reach us.
"""
import base64
import datetime
import json
import os

# The PQgate license-signing public key, bundled deliberately. It is a *public*
# key: shipping it lets an air-gapped host verify a license with no network at all.
# Empty until a release key exists; `license verify` says so rather than pretending.
LICENSE_PUBLIC_KEY_B64 = ""

LICENSE_PATHS = (
    os.path.join(".pqgate", "license.json"),
    os.path.expanduser(os.path.join("~", ".pqgate", "license.json")),
)

# What a license can grant. Anything not listed is free and always will be.
ENTITLEMENTS = {
    "rules:update": "Install newer signed rule packs",
    "cmvp:refresh": "Refreshed CMVP certificate data from our feed",
    "profiles:custom": "Vendor-maintained compliance profiles",
    "evidence:api": "Evidence API and assessor portal links",
    "support": "Named support contact",
}

# Everything below is free forever, license or not. Written down so the boundary is
# reviewable rather than a matter of opinion.
ALWAYS_FREE = (
    "Scanning, at every layer, with the rule packs you have",
    "All compliance profiles that ship with the release",
    "CBOM, SARIF and readiness reports",
    "Evidence signing and verification",
    "The local evidence server and web app",
    "Importing your own CMVP export",
    "The GitHub Action and GitLab template",
)


class LicenseError(ValueError):
    pass


class License:
    def __init__(self, doc, verified=False, reason=""):
        self.doc = doc or {}
        self.verified = verified
        self.reason = reason

    # -- fields -----------------------------------------------------------
    @property
    def org(self):
        return self.doc.get("org", "unlicensed")

    @property
    def tier(self):
        return self.doc.get("tier", "open")

    @property
    def entitlements(self):
        return tuple(self.doc.get("entitlements") or ())

    @property
    def expires(self):
        raw = self.doc.get("expires")
        return datetime.date.fromisoformat(raw) if raw else None

    # -- state ------------------------------------------------------------
    def expired(self, today=None):
        expires = self.expires
        return bool(expires and expires < (today or datetime.date.today()))

    def days_left(self, today=None):
        expires = self.expires
        if not expires:
            return None
        return (expires - (today or datetime.date.today())).days

    def grants(self, entitlement, today=None):
        return (self.verified and not self.expired(today)
                and entitlement in self.entitlements)

    def status(self, today=None):
        if not self.doc:
            return "none"
        if not self.verified:
            return "unverified"
        if self.expired(today):
            return "expired"
        return "active"

    def describe(self, today=None):
        state = self.status(today)
        if state == "none":
            return "no license installed - scanning is free and unaffected"
        if state == "unverified":
            return "license signature could not be verified: " + (self.reason or "unknown")
        if state == "expired":
            return ("license for " + self.org + " expired " + str(self.expires) +
                    " - installed rule packs keep working, updates do not")
        return (self.tier + " license for " + self.org + ", " +
                str(self.days_left(today)) + " days remaining")


UNLICENSED = License({}, verified=False)


# --------------------------------------------------------------------------
def signing_payload(doc):
    """Bytes the license signature covers: the document minus its own signature."""
    from .outputs import canonical
    stripped = json.loads(json.dumps(doc))
    stripped.pop("signature", None)
    return canonical(stripped)


def verify_license(doc, public_key_b64=None):
    """Verify a license document offline. Returns a License."""
    key_b64 = public_key_b64 if public_key_b64 is not None else LICENSE_PUBLIC_KEY_B64
    if not doc.get("signature"):
        return License(doc, False, "the license carries no signature")
    if not key_b64:
        return License(doc, False,
                       "no license-signing public key is bundled in this build, so the "
                       "signature cannot be checked (releases ship one)")
    try:
        from .signing import get_signer
        signer = get_signer()
    except Exception as exc:
        return License(doc, False, "no ML-DSA-87 backend available: " + str(exc).splitlines()[0])

    try:
        ok = signer.verify(base64.b64decode(key_b64),
                           signing_payload(doc),
                           base64.b64decode(doc["signature"]))
    except Exception as exc:
        return License(doc, False, "malformed signature: " + str(exc))
    if not ok:
        return License(doc, False, "signature does not verify against the bundled key")
    return License(doc, True)


def find_license(path=None):
    """Locate a license: explicit path, PQGATE_LICENSE, then the usual places."""
    candidates = []
    if path:
        candidates.append(path)
    if os.environ.get("PQGATE_LICENSE"):
        candidates.append(os.environ["PQGATE_LICENSE"])
    candidates.extend(LICENSE_PATHS)
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def load_license(path=None):
    found = find_license(path)
    if not found:
        return UNLICENSED
    try:
        with open(found, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return License({}, False, "could not read " + found + ": " + str(exc))
    license_ = verify_license(doc)
    license_.path = found
    return license_


def require(entitlement, path=None):
    """Raise unless the installed license grants `entitlement`.

    Only ever called on update paths. Nothing in the scan path calls this.
    """
    license_ = load_license(path)
    if license_.grants(entitlement):
        return license_
    raise LicenseError(
        "this action needs the '" + entitlement + "' entitlement (" +
        ENTITLEMENTS.get(entitlement, entitlement) + ").\n" +
        "  Current: " + license_.describe() + "\n"
        "  Scanning is unaffected and always will be - the rule packs you already have "
        "keep working.\n"
        "  Install a license: pqgate license install <license.json>")
