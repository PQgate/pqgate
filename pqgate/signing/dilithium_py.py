"""dilithium-py backend - DEVELOPMENT ONLY.

Pure Python, and its own authors describe it as educational rather than production
software. It is here because it installs on any machine with no native dependency,
which makes demos and CI possible. It is not a cryptographic module in any sense a
programme office would accept, and the FIPS profiles refuse it by default.
"""
from . import Signer


class DilithiumPySigner(Signer):
    id = "dilithium-py"
    module_id = "dilithium-py"
    validated = False
    audited = False
    description = "pure-Python ML-DSA-87 (educational; development only)"

    @classmethod
    def available(cls):
        try:
            import dilithium_py.ml_dsa  # noqa: F401
            return True
        except ImportError:
            return False

    @classmethod
    def unavailable_reason(cls):
        return "dilithium-py is not installed (pip install dilithium-py)"

    @staticmethod
    def _impl():
        from dilithium_py.ml_dsa import ML_DSA_87
        return ML_DSA_87

    def keygen(self):
        return self._impl().keygen()

    def sign(self, private_key, message):
        return self._impl().sign(private_key, message)

    def verify(self, public_key, message, signature):
        try:
            return bool(self._impl().verify(public_key, message, signature))
        except Exception:
            return False
