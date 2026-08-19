"""Evidence signing.

Adds authenticity (who produced this) on top of the integrity the SHA-384 content hash
already provides (has this been altered).

Engineering rule 1 applies with full force here: this package implements no
cryptography. It defines a `Signer` interface and selects among pluggable backends,
each of which declares which cryptographic module it is and whether that module is
CMVP-validated. That declaration flows into the signature block, so a verifier can
tell the difference between "signed" and "signed by a validated module" - a distinction
that matters a great deal to the buyer and not at all to a naive implementation.

Backends, in preference order:
  liboqs        - bindings over a reviewed C library. Not CMVP-validated.
  dilithium-py  - pure Python, self-declared educational. DEVELOPMENT ONLY.
  pkcs11        - the seam where a validated HSM plugs in (PQforge).
"""
import os

ALGORITHM = "ML-DSA-87"
STANDARD = "FIPS 204"


class SigningError(RuntimeError):
    pass


class BackendUnavailable(SigningError):
    pass


class Signer:
    """Interface every backend implements.

    id          stable backend name used in --signer and in the signature block
    module_id   key into pqgate/rules/cmvp.yml, so the signer is subject to the
                same module-validation posture as any scanned dependency
    validated   whether that module is CMVP-validated
    audited     whether the implementation has had meaningful third-party review;
                distinct from `validated`, and an unaudited implementation is worse
    """

    id = "abstract"
    module_id = None
    validated = False
    audited = False
    algorithm = ALGORITHM
    standard = STANDARD
    description = ""

    @classmethod
    def available(cls):
        raise NotImplementedError

    @classmethod
    def unavailable_reason(cls):
        return "backend not available"

    def keygen(self):
        raise NotImplementedError

    def sign(self, private_key, message):
        raise NotImplementedError

    def verify(self, public_key, message, signature):
        raise NotImplementedError


def _backends():
    from .dilithium_py import DilithiumPySigner
    from .liboqs import LiboqsSigner
    from .pkcs11 import Pkcs11Signer
    return [LiboqsSigner, DilithiumPySigner, Pkcs11Signer]


def registry():
    return {b.id: b for b in _backends()}


def available_backends():
    return [b for b in _backends() if b.available()]


def get_signer(name=None):
    """Resolve a backend by name, or pick the best available one.

    Preference order is deliberate: a reviewed C library beats a pure-Python one, and
    neither is silently substituted for the other.
    """
    name = name or os.environ.get("PQGATE_SIGNER")
    if name:
        backend = registry().get(name)
        if backend is None:
            raise SigningError("unknown signer backend: " + name +
                               " (available: " + ", ".join(sorted(registry())) + ")")
        if not backend.available():
            raise BackendUnavailable(name + " is not available: " + backend.unavailable_reason())
        return backend()

    for backend in _backends():
        if backend.available():
            return backend()
    raise BackendUnavailable(
        "no ML-DSA-87 backend available. Install one:\n"
        "  pip install liboqs-python   (bindings over a reviewed C library)\n"
        "  pip install dilithium-py    (pure Python, DEVELOPMENT ONLY)")


# Profiles that require a validated cryptographic module for the signer itself.
VALIDATED_MODULE_PROFILES = {"fips-140-3", "cnsa-2.0-fips"}


def check_signer_allowed(signer, profile_name, allow_unvalidated=False):
    """Refuse to sign compliance evidence with an unvalidated module under a FIPS profile.

    Signing a FIPS 140-3 attestation with an unaudited implementation is exactly the
    contradiction this product exists to catch. It stays possible - some evaluations
    genuinely need a demo - but only when asked for explicitly, and the signature block
    records that it happened.
    """
    if profile_name not in VALIDATED_MODULE_PROFILES:
        return None
    if signer.validated:
        return None
    if allow_unvalidated:
        return ("signed under profile '" + profile_name + "' with " + signer.id +
                ", which is not a CMVP-validated module - recorded in the signature block")
    raise SigningError(
        "profile '" + profile_name + "' requires a CMVP-validated signing module, and " +
        signer.id + " is not one" +
        ("" if signer.audited else " (and is not an audited implementation)") + ".\n"
        "Use a PKCS#11 backend, or pass --allow-unvalidated-signer to sign anyway; the "
        "signature block will record that the module was unvalidated.")
