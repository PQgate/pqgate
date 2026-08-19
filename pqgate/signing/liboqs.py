"""liboqs backend.

Bindings over the Open Quantum Safe C library: a reviewed implementation with real
usage, but not a CMVP-validated cryptographic module. That distinction is preserved
rather than blurred - `audited` is True, `validated` is False - because a FIPS 140-3
requirement is not satisfied by "the code is good".

AIR-GAP WARNING, and the reason this file is more careful than it looks:

    `import oqs` has a side effect. When the native shared library is missing, the
    liboqs-python package clones liboqs from GitHub and builds it, at import time.
    That is a network call, and it executes code fetched at runtime - both
    disqualifying in the environments this product targets.

So availability is probed WITHOUT importing: the module spec is located, and the
shared library is looked for on disk. The package is imported only once a caller has
explicitly selected this backend and a library is already present. Engineering rule 2
does not have an exception for convenience.
"""
import ctypes.util
import importlib.util
import os

from . import Signer

_MECHANISM = "ML-DSA-87"
_LIB_NAMES = ("oqs.dll", "liboqs.dll", "liboqs.so", "liboqs.dylib")


def _library_path():
    """Locate a pre-installed liboqs without importing anything that might fetch one."""
    roots = []
    if os.environ.get("OQS_INSTALL_PATH"):
        roots.append(os.environ["OQS_INSTALL_PATH"])
    home = os.path.expanduser("~")
    roots += [os.path.join(home, "_oqs"), os.path.join(home, "_oqs", "lib"),
              os.path.join(home, "_oqs", "bin")]
    for root in roots:
        for name in _LIB_NAMES:
            candidate = os.path.join(root, name)
            if os.path.exists(candidate):
                return candidate
    found = ctypes.util.find_library("oqs")   # filesystem/ldconfig lookup, no network
    return found or None


class LiboqsSigner(Signer):
    id = "liboqs"
    module_id = "liboqs"
    validated = False
    audited = True
    description = "liboqs ML-DSA-87 (reviewed C implementation, not CMVP-validated)"

    @classmethod
    def available(cls):
        if importlib.util.find_spec("oqs") is None:
            return False
        return _library_path() is not None

    @classmethod
    def unavailable_reason(cls):
        if importlib.util.find_spec("oqs") is None:
            return "liboqs-python is not installed (pip install liboqs-python)"
        return ("liboqs-python is installed but no native liboqs library was found. "
                "PQgate will not import it in this state: liboqs-python builds the "
                "library from a GitHub clone at import time, which is a network call and "
                "runs code fetched at runtime. Install liboqs out of band and set "
                "OQS_INSTALL_PATH.")

    @staticmethod
    def _oqs():
        import oqs
        return oqs

    def keygen(self):
        with self._oqs().Signature(_MECHANISM) as sig:
            public_key = sig.generate_keypair()
            return public_key, sig.export_secret_key()

    def sign(self, private_key, message):
        with self._oqs().Signature(_MECHANISM, private_key) as sig:
            return sig.sign(message)

    def verify(self, public_key, message, signature):
        try:
            with self._oqs().Signature(_MECHANISM) as sig:
                return bool(sig.verify(message, signature, public_key))
        except Exception:
            return False
