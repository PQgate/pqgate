"""PKCS#11 backend - the seam where a validated HSM plugs in.

Deliberately not implemented. This is where PQforge's `keystore` abstraction
lands (Phase 3): key material never leaves the token, the signature is produced
inside the validated boundary, and `validated` becomes true for real rather than by
assertion.

It exists now so the interface is shaped correctly and the FIPS profile check has
something to point at.
"""
from . import Signer, SigningError


class Pkcs11Signer(Signer):
    id = "pkcs11"
    module_id = None  # resolved from the token at runtime
    validated = True
    audited = True
    description = "PKCS#11 token / HSM (not implemented - PQforge, Phase 3)"

    @classmethod
    def available(cls):
        return False

    @classmethod
    def unavailable_reason(cls):
        return ("PKCS#11 signing is not implemented yet; it arrives with PQforge "
                "(see docs/release-roadmap.md)")

    def keygen(self):
        raise SigningError(self.unavailable_reason())

    def sign(self, private_key, message):
        raise SigningError(self.unavailable_reason())

    def verify(self, public_key, message, signature):
        raise SigningError(self.unavailable_reason())
