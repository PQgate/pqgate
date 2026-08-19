"""Compliance profiles. Built-ins are code; custom profiles load from YAML."""
import copy
import os

import yaml

# Action to take per classification. "pass" means compliant, counted in the score.
BUILTIN_PROFILES = {
    "cnsa-2.0": {
        "description": "NSA CNSA 2.0 for National Security Systems",
        "actions": {
            "quantum-vulnerable": "block",
            "weak-hash": "block",
            "committed-key": "block",
            "hash-below-profile": "warn",
            "sym-below-profile": "warn",
            "pqc-below-profile": "warn",
            "lib-capability": "warn",
            "pqc-safe": "pass",
            # SC-12 — key establishment and management.
            "keygen-not-approved": "block",
            "keygen-hardcoded": "block",
            "keyestab-not-approved": "block",
            "module-cert-historical": "block",
            "module-not-validated": "warn",
            "keymgmt-no-rotation": "warn",
            "keymgmt-below-strength": "warn",
        },
        # CNSA 2.0 exactness: ML-KEM-1024 / ML-DSA-87 only, plus SP 800-208 hash sigs.
        "pqc_ok": ("ML-KEM-1024", "ML-DSA-87", "MLKEM1024", "DILITHIUM5", "LMS", "XMSS"),
        "pqc_low": ("512", "768", "44", "65", "KYBER512", "KYBER768",
                    "DILITHIUM2", "DILITHIUM3", "ML-KEM-512", "ML-KEM-768",
                    "ML-DSA-44", "ML-DSA-65"),
        "milestones": {"new_acquisitions": "2027-01-01", "full_transition": "2033-01-01"},
    },
    "nist-baseline": {
        "description": "NIST FIPS 203/204/205 baseline (any parameter set)",
        "actions": {
            "quantum-vulnerable": "warn",
            "weak-hash": "block",
            "committed-key": "block",
            "hash-below-profile": "pass",
            "sym-below-profile": "warn",
            "pqc-below-profile": "pass",
            "lib-capability": "warn",
            "pqc-safe": "pass",
            "keygen-not-approved": "block",
            "keygen-hardcoded": "block",
            "keyestab-not-approved": "warn",
            "module-cert-historical": "warn",
            "module-not-validated": "pass",
            "keymgmt-no-rotation": "warn",
            "keymgmt-below-strength": "warn",
        },
        "pqc_ok": ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "LMS", "XMSS"),
        "pqc_low": (),
        "milestones": {},
    },
}

# The FIPS profile is orthogonal to CNSA 2.0: a module can be validated and still use
# quantum-vulnerable algorithms, and vice versa. Programmes that need both run the
# combined profile.
BUILTIN_PROFILES["fips-140-3"] = {
    "description": "FIPS 140-3 module validation and SP 800-56/57/133 key management",
    "actions": {
        # SC-12 is the point of this profile; SC-13 stays advisory.
        "module-not-validated": "block",
        "module-cert-historical": "block",
        "keygen-not-approved": "block",
        "keygen-hardcoded": "block",
        "keyestab-not-approved": "block",
        "keymgmt-no-rotation": "warn",
        "keymgmt-below-strength": "warn",
        "weak-hash": "block",
        "committed-key": "block",
        "sym-below-profile": "warn",
        "hash-below-profile": "warn",
        "quantum-vulnerable": "warn",
        "pqc-below-profile": "pass",
        "lib-capability": "warn",
        "pqc-safe": "pass",
    },
    "pqc_ok": ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS"),
    "pqc_low": (),
    "milestones": {},
}

BUILTIN_PROFILES["cnsa-2.0-fips"] = {
    "description": "CNSA 2.0 algorithms inside a FIPS 140-3 validated boundary",
    "actions": dict(BUILTIN_PROFILES["cnsa-2.0"]["actions"],
                    **{"module-not-validated": "block"}),
    "pqc_ok": BUILTIN_PROFILES["cnsa-2.0"]["pqc_ok"],
    "pqc_low": BUILTIN_PROFILES["cnsa-2.0"]["pqc_low"],
    "milestones": BUILTIN_PROFILES["cnsa-2.0"]["milestones"],
}

REQUIRED_CLASSES = set(BUILTIN_PROFILES["cnsa-2.0"]["actions"])
VALID_ACTIONS = {"block", "warn", "pass", "ignore"}


class ProfileError(ValueError):
    pass


def _validate(name, prof):
    missing = REQUIRED_CLASSES - set(prof.get("actions", {}))
    if missing:
        raise ProfileError(f"profile '{name}': missing actions for {sorted(missing)}")
    bad = {a for a in prof["actions"].values() if a not in VALID_ACTIONS}
    if bad:
        raise ProfileError(f"profile '{name}': invalid actions {sorted(bad)}")
    return prof


def load_profiles(custom_dir=None):
    """Built-ins plus any *.yml in custom_dir (each file defines one profile)."""
    profiles = copy.deepcopy(BUILTIN_PROFILES)
    if custom_dir and os.path.isdir(custom_dir):
        for fname in sorted(os.listdir(custom_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            with open(os.path.join(custom_dir, fname), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            name = doc.get("name") or os.path.splitext(fname)[0]
            base = doc.get("extends")
            prof = copy.deepcopy(profiles[base]) if base in profiles else {"actions": {}}
            prof.update({k: v for k, v in doc.items() if k not in ("name", "extends", "actions")})
            prof.setdefault("actions", {}).update(doc.get("actions") or {})
            for key in ("pqc_ok", "pqc_low"):
                if key in doc:
                    prof[key] = tuple(doc[key])
            profiles[name] = _validate(name, prof)
    return profiles


def get_profile(name, custom_dir=None):
    profiles = load_profiles(custom_dir)
    if name not in profiles:
        raise ProfileError(f"unknown profile: {name} (available: {', '.join(sorted(profiles))})")
    return profiles[name]
