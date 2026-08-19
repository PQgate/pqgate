"""Rule packs, loaded from YAML data files so rules ship independently of the engine.

Two axes per rule:
  classification -> what kind of cryptographic problem this is (the profile decides
                    whether that blocks, warns or passes)
  controls       -> which NIST SP 800-53 controls the finding is evidence for, and
                    which standards define the requirement

The second axis is what lets one scan produce both an SC-13 algorithm posture and an
SC-12 key-establishment/management posture from the same pass.
"""
import fnmatch
import os
import re
from dataclasses import dataclass
from typing import Optional

import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))

# SC-13 — algorithm selection.
ALGORITHM_CLASSES = {
    "quantum-vulnerable", "weak-hash", "committed-key", "hash-below-profile",
    "sym-below-profile", "pqc-below-profile", "lib-capability", "pqc-safe",
}

# SC-12 — key establishment and management.
KEY_CLASSES = {
    "module-not-validated",     # FIPS 140-3: no CMVP validation for this module
    "module-cert-historical",   # FIPS 140-2/3: certificate moved to the historical list
    "keyestab-not-approved",    # SP 800-56A/B/C: unapproved scheme or missing KDF
    "keygen-not-approved",      # SP 800-133 / 800-90A: key material from a non-approved RBG
    "keygen-hardcoded",         # SP 800-133: key material literal in source
    "keymgmt-no-rotation",      # SP 800-57: rotation disabled or crypto period exceeded
    "keymgmt-below-strength",   # SP 800-57: key length below the recommended strength
}

VALID_CLASSES = ALGORITHM_CLASSES | KEY_CLASSES

# Every control we can currently produce evidence for.
KNOWN_CONTROLS = {"SC-12", "SC-13", "SA-11", "RA-5", "CM-3", "IA-7", "SC-28"}

CONTROL_TITLES = {
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SA-11": "Developer Testing and Evaluation",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "CM-3": "Configuration Change Control",
    "IA-7": "Cryptographic Module Authentication",
}

# Packs merged into the source-language rule set. Order is stable so rule ids stay
# deterministic in output.
SOURCE_PACKS = ("source.yml", "keygen.yml", "keyestab.yml")
FILE_PACKS = ("config.yml", "iac.yml")


@dataclass(frozen=True)
class Rule:
    id: str
    langs: tuple
    regex: "re.Pattern"
    classification: str
    message: str
    controls: tuple = ()
    standards: tuple = ()
    remediation: str = ""
    files: tuple = ()
    ast_calls: tuple = ()
    ast_literal_arg: Optional[int] = None
    key_context: bool = False

    def matches_file(self, basename):
        return any(fnmatch.fnmatch(basename, pat) for pat in self.files)


class RuleSetError(ValueError):
    pass


def _compile(raw, path):
    for key in ("id", "regex", "class", "message"):
        if key not in raw:
            raise RuleSetError(f"{path}: rule missing required key '{key}': {raw!r}")
    if not raw.get("lang") and not raw.get("files"):
        raise RuleSetError(f"{path}: rule {raw['id']}: needs 'lang' or 'files'")
    if raw["class"] not in VALID_CLASSES:
        raise RuleSetError(f"{path}: rule {raw['id']}: unknown class '{raw['class']}'")
    unknown = set(raw.get("controls") or ()) - KNOWN_CONTROLS
    if unknown:
        raise RuleSetError(f"{path}: rule {raw['id']}: unknown controls {sorted(unknown)}")
    if raw["class"] in KEY_CLASSES and not raw.get("controls"):
        raise RuleSetError(f"{path}: rule {raw['id']}: SC-12 class needs a 'controls' list")
    try:
        return re.compile(raw["regex"])
    except re.error as e:
        raise RuleSetError(f"{path}: rule {raw['id']}: bad regex: {e}") from e


def _build(raw, path):
    rx = _compile(raw, path)
    ast_cfg = raw.get("ast") or {}
    return Rule(
        id=raw["id"],
        langs=tuple(raw.get("lang") or ()),
        regex=rx,
        classification=raw["class"],
        message=raw["message"],
        controls=tuple(raw.get("controls") or ()),
        standards=tuple(raw.get("standards") or ()),
        remediation=raw.get("remediation", ""),
        files=tuple(raw.get("files") or ()),
        ast_calls=tuple(ast_cfg.get("calls", ())),
        ast_literal_arg=ast_cfg.get("literal_arg"),
        key_context=bool(raw.get("key_context", False)),
    )


def _read_pack(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_rules(path=None, packs=SOURCE_PACKS):
    """Return {ext: [Rule, ...]} for source-language rules."""
    paths = [path] if path else [os.path.join(_HERE, p) for p in packs]
    by_ext, seen = {}, set()
    for p in paths:
        if not os.path.exists(p):
            continue
        for raw in _read_pack(p).get("rules", []):
            rule = _build(raw, p)
            if rule.id in seen:
                raise RuleSetError(f"{p}: duplicate rule id '{rule.id}'")
            seen.add(rule.id)
            for ext in rule.langs:
                by_ext.setdefault(ext, []).append(rule)
    return by_ext


def load_file_rules(path=None, packs=FILE_PACKS):
    """Return [Rule, ...] matched by filename glob rather than extension.

    Configuration is where cipher choice actually lives — nginx, sshd, java.security,
    openssl.cnf, and infrastructure-as-code — so it gets its own matcher.
    """
    paths = [path] if path else [os.path.join(_HERE, p) for p in packs]
    out, seen = [], set()
    for p in paths:
        if not os.path.exists(p):
            continue
        for raw in _read_pack(p).get("rules", []):
            rule = _build(raw, p)
            if rule.id in seen:
                raise RuleSetError(f"{p}: duplicate rule id '{rule.id}'")
            seen.add(rule.id)
            out.append(rule)
    return out


def load_manifests(path=None):
    """Return {manifest_filename: {package: {...}}}."""
    path = path or os.path.join(_HERE, "manifests.yml")
    doc = _read_pack(path)
    out = {}
    for fname, pkgs in (doc.get("manifests") or {}).items():
        entry = {}
        for pkg, meta in pkgs.items():
            if meta.get("class") not in VALID_CLASSES:
                raise RuleSetError(f"{path}: {fname}/{pkg}: unknown class '{meta.get('class')}'")
            entry[pkg] = {
                "class": meta["class"],
                "message": meta["message"],
                "controls": tuple(meta.get("controls") or ("SC-13",)),
                "standards": tuple(meta.get("standards") or ()),
                "module": meta.get("module"),
            }
        out[fname] = entry
    return out


def load_cmvp(path=None):
    """Cryptographic module validation posture, keyed by module id.

    Certificate numbers and sunset dates are deliberately NOT bundled: they come from
    the operator's own CMVP export (`pqgate cmvp import`). What ships here is the
    stable part — which distribution of a library is the validated one, which is not,
    and under which standard. See docs/sc-12-control-mapping.md.
    """
    path = path or os.path.join(_HERE, "cmvp.yml")
    doc = _read_pack(path)
    modules = {}
    for mid, meta in (doc.get("modules") or {}).items():
        modules[mid] = {
            "id": mid,
            "name": meta.get("name", mid),
            "vendor": meta.get("vendor", ""),
            "validated": bool(meta.get("validated", False)),
            "standard": meta.get("standard"),
            "note": meta.get("note", ""),
            "instead_of": meta.get("instead_of"),
            # Populated by `pqgate cmvp import`; never shipped pre-filled.
            "cert": meta.get("cert"),
            "status": meta.get("status"),
            "sunset": meta.get("sunset"),
        }
    for mid, overlay in load_cmvp_overlay().items():
        if mid in modules:
            modules[mid].update({k: v for k, v in overlay.items() if v is not None})
    return modules


CMVP_OVERLAY = os.path.join(_HERE, "cmvp-certificates.yml")


def load_cmvp_overlay(path=None):
    """Certificate numbers, status and sunset dates imported from the operator's own
    CMVP export. Never shipped in the repository - see cmvp.yml for why."""
    path = path or CMVP_OVERLAY
    if not os.path.exists(path):
        return {}
    return (_read_pack(path).get("modules") or {})


def save_cmvp_overlay(modules, path=None):
    path = path or CMVP_OVERLAY
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Imported from a CMVP export by `pqgate cmvp import`.\n"
                 "# Not tracked in version control: certificate status changes over time,\n"
                 "# and a stale copy would let PQgate assert a lapsed certificate is current.\n")
        yaml.safe_dump({"modules": modules}, fh, sort_keys=True)
    return path


# A rule pack older than this reports as stale. Not an expiry - the pack keeps
# working - but a scan says so, because a stale pack quietly reports clean.
STALE_AFTER_DAYS = 90

ALL_PACKS = SOURCE_PACKS + FILE_PACKS + ("manifests.yml", "cmvp.yml")


def pack_metadata(packs=ALL_PACKS):
    """Name, description and release date for each installed pack, with its age."""
    import datetime
    today = datetime.date.today()
    out = []
    for name in packs:
        path = os.path.join(_HERE, name)
        if not os.path.exists(path):
            continue
        meta = (_read_pack(path).get("pack") or {})
        released = meta.get("released")
        age = None
        if released:
            try:
                age = (today - datetime.date.fromisoformat(str(released))).days
            except ValueError:
                age = None
        out.append({
            "file": name,
            "name": meta.get("name", name.replace(".yml", "")),
            "description": meta.get("description", ""),
            "released": str(released) if released else None,
            "age_days": age,
            "stale": bool(age is not None and age > STALE_AFTER_DAYS),
        })
    return out


def stale_packs(packs=ALL_PACKS):
    return [p for p in pack_metadata(packs) if p["stale"]]


def all_rules(path=None):
    seen, out = set(), []
    for rules in load_rules(path).values():
        for r in rules:
            if r.id not in seen:
                seen.add(r.id)
                out.append(r)
    for r in load_file_rules():
        if r.id not in seen:
            seen.add(r.id)
            out.append(r)
    return out
