"""Key storage and the trust store.

Two very different things live here:

  The KEYSTORE holds a private key. The file-backed one is for development only and
  says so in its filename, because chmod(0o600) is a no-op on Windows and a private
  key on a developer's disk is not a key-management story anyone will accept. The
  real answer is a PKCS#11 token; this is the placeholder that keeps the interface
  honest until PQforge provides one.

  The TRUST STORE holds public key fingerprints someone has decided to believe. It is
  tracked in version control on purpose: adding a key that can sign your compliance
  evidence should appear in a pull request, with a reviewer.
"""
import datetime
import hashlib
import os

import yaml

DEV_KEY_DIR = ".pqgate-keys"
DEV_PRIVATE_KEY = "evidence.key.INSECURE-DEV"
PUBLIC_KEY = "evidence.pub"
TRUST_STORE = os.path.join(".pqgate", "trusted-keys.yml")

DEV_WARNING = (
    "This private key is stored unprotected on local disk. It is a development "
    "convenience, not key management: file permissions are advisory at best and a "
    "no-op on Windows. Production signing keys belong in a PKCS#11 token."
)


class KeystoreError(RuntimeError):
    pass


def fingerprint(public_key):
    """SHA-384 over the raw public key. Short form is used in output; full form is
    what the trust store pins."""
    return "sha384:" + hashlib.sha384(public_key).hexdigest()


def short(fp):
    body = fp.replace("sha384:", "")
    return "sha384:" + body[:16] + "..."


# --------------------------------------------------------------------------
# Development keystore
# --------------------------------------------------------------------------
def key_paths(directory=None):
    directory = directory or DEV_KEY_DIR
    return (os.path.join(directory, DEV_PRIVATE_KEY),
            os.path.join(directory, PUBLIC_KEY))


def generate(signer, directory=None, force=False):
    directory = directory or DEV_KEY_DIR
    private_path, public_path = key_paths(directory)
    if os.path.exists(private_path) and not force:
        raise KeystoreError("refusing to overwrite an existing key at " + private_path +
                            " (pass --force if that is what you want)")
    os.makedirs(directory, exist_ok=True)
    public_key, private_key = signer.keygen()
    with open(public_path, "wb") as fh:
        fh.write(public_key)
    with open(private_path, "wb") as fh:
        fh.write(private_key)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    return {
        "public_path": public_path,
        "private_path": private_path,
        "fingerprint": fingerprint(public_key),
        "public_bytes": len(public_key),
        "private_bytes": len(private_key),
        "signer": signer.id,
    }


def load(directory=None):
    private_path, public_path = key_paths(directory)
    if not os.path.exists(private_path):
        raise KeystoreError("no signing key at " + private_path +
                            " - run: pqgate keys generate")
    with open(private_path, "rb") as fh:
        private_key = fh.read()
    with open(public_path, "rb") as fh:
        public_key = fh.read()
    return private_key, public_key


# --------------------------------------------------------------------------
# Trust store
# --------------------------------------------------------------------------
def load_trust(path=None):
    path = path or TRUST_STORE
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return {k: v for k, v in (doc.get("keys") or {}).items()}


def trust(public_key_path, name, path=None, algorithm="ML-DSA-87"):
    path = path or TRUST_STORE
    with open(public_key_path, "rb") as fh:
        public_key = fh.read()
    fp = fingerprint(public_key)
    keys = load_trust(path)
    keys[fp] = {
        "name": name,
        "algorithm": algorithm,
        "added": datetime.date.today().isoformat(),
        "publicKeyBytes": len(public_key),
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Public keys trusted to sign PQgate evidence.\n"
                 "# Tracked deliberately: adding a key that can sign your compliance\n"
                 "# evidence should go through review like any other change.\n"
                 "# Manage with: pqgate keys trust <evidence.pub> --name '...'\n")
        yaml.safe_dump({"keys": keys}, fh, sort_keys=True)
    return fp, path


def is_trusted(fp, path=None):
    return fp in load_trust(path)
