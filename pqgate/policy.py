"""Policy engine: .pqgate.yml -> final action per finding.

Resolution order: profile default -> matching policies (last match wins) -> exceptions.
Exceptions require both `reason` and `expires`; an expired exception restores
enforcement and emits a NOTE.
"""
import copy
import datetime
import fnmatch
import os
import subprocess

import yaml

from .profiles import get_profile

DEFAULT_POLICY = {
    "version": 1,
    "profile": "cnsa-2.0",
    "policies": [],
    "exceptions": [],
    "reporting": {"fail_build_on": "block"},
}

VALID_SCOPES = {"all-code", "new-code-only"}
VALID_ACTIONS = {"block", "warn", "ignore", "pass"}


class PolicyError(ValueError):
    pass


def load_policy(path, profile_override=None, custom_profile_dir=None):
    pol = copy.deepcopy(DEFAULT_POLICY)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
        if not isinstance(user, dict):
            raise PolicyError(str(path) + ": policy file must be a YAML mapping")
        pol.update(user)
    if profile_override:
        pol["profile"] = profile_override
    validate_policy(pol, custom_profile_dir)
    return pol


def validate_policy(pol, custom_profile_dir=None):
    get_profile(pol["profile"], custom_profile_dir)  # raises ProfileError if unknown

    ids = set()
    for p in pol.get("policies") or []:
        pid = p.get("id")
        if not pid:
            raise PolicyError("policy entry missing 'id': " + repr(p))
        if pid in ids:
            raise PolicyError("duplicate policy id: " + pid)
        ids.add(pid)
        if p.get("scope", "all-code") not in VALID_SCOPES:
            raise PolicyError("policy " + pid + ": scope must be one of " + str(sorted(VALID_SCOPES)))
        if p.get("action", "block") not in VALID_ACTIONS:
            raise PolicyError("policy " + pid + ": invalid action " + repr(p.get("action")))
        if not p.get("match") and not p.get("paths"):
            raise PolicyError("policy " + pid + ": needs at least one of 'match' or 'paths'")

    for ex in pol.get("exceptions") or []:
        ref = ex.get("policy")
        if not ref:
            raise PolicyError("exception missing 'policy' reference: " + repr(ex))
        if not ex.get("reason"):
            raise PolicyError("exception for '" + str(ref) + "': 'reason' is required")
        if not ex.get("expires"):
            raise PolicyError("exception for '" + str(ref) + "': 'expires' is required (ISO date)")
        try:
            parse_date(ex["expires"])
        except ValueError as e:
            raise PolicyError("exception for '" + str(ref) + "': bad expires date: " + str(e)) from e
    return pol


def parse_date(d):
    if isinstance(d, datetime.date):
        return d
    return datetime.date.fromisoformat(str(d))


def _match_policy(finding, match):
    if not match:
        return True  # paths-only policy
    if "classification" in match and finding["classification"] != match["classification"]:
        return False
    if "finding_type" in match and finding["classification"] != match["finding_type"]:
        return False
    if "rule" in match:
        rules = match["rule"] if isinstance(match["rule"], list) else [match["rule"]]
        if not any(fnmatch.fnmatch(finding["rule"], r) for r in rules):
            return False
    if "algorithm" in match:
        algs = match["algorithm"] if isinstance(match["algorithm"], list) else [match["algorithm"]]
        hay = (finding["message"] + " " + finding["rule"] + " " + finding["evidence"]).lower()
        if not any(str(a).lower() in hay for a in algs):
            return False
    return True


def match_paths(path, patterns):
    # Normalise backslashes explicitly rather than via os.sep. Using os.sep makes this
    # platform-dependent: a Windows-style path would match on Windows and silently fail
    # to match on the Linux runner that actually gates the merge.
    norm = str(path).replace("\\", "/")
    for pat in patterns:
        pat = str(pat).replace("\\", "/")
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(norm, "*/" + pat.lstrip("/")):
            return True
        # `legacy/**` should also match `legacy/x.py` and `demo-repo/legacy/x.py`
        if pat.endswith("/**"):
            base = pat[:-3]
            if norm == base or ("/" + norm).find("/" + base + "/") >= 0 or norm.startswith(base + "/"):
                return True
    return False


def git_changed_files(root, base_ref):
    """Files changed since base_ref, as normalized paths relative to the scan root."""
    proc = subprocess.run(["git", "-C", root, "diff", "--name-only", base_ref, "HEAD"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise PolicyError("git diff failed for base '" + base_ref + "': " + proc.stderr.strip())
    return {os.path.normpath(os.path.join(root, p)) for p in proc.stdout.splitlines() if p.strip()}


def apply_policy(findings, pol, changed_files=None, today=None, custom_profile_dir=None):
    """Annotate findings with action/policy_id/exception. Returns (kept, notes).

    Findings resolved to `ignore` are dropped from the returned list but are still
    represented by their exception record in the exceptions register.
    """
    today = today or datetime.date.today()
    profile = get_profile(pol["profile"], custom_profile_dir)
    policies = pol.get("policies") or []
    exceptions = pol.get("exceptions") or []
    notes, expired_seen = [], set()

    if changed_files is None and any(p.get("scope") == "new-code-only" for p in policies):
        notes.append("new-code-only policies present but no --diff-base given - "
                     "those policies were not applied")

    for f in findings:
        action = profile["actions"].get(f["classification"], "warn")
        f["policy_id"] = "profile:" + pol["profile"]
        f.pop("exception", None)

        for p in policies:
            if not _match_policy(f, p.get("match")):
                continue
            if p.get("paths") and not match_paths(f["file"], p["paths"]):
                continue
            if p.get("scope", "all-code") == "new-code-only":
                if changed_files is None or f["file"] not in changed_files:
                    continue
            action = p.get("action", action)
            f["policy_id"] = p["id"]

        applied_id = f["policy_id"].split(":")[-1]
        for ex in exceptions:
            ref = ex.get("policy")
            if ref != "*" and ref != applied_id and ref != f["policy_id"]:
                continue
            if ex.get("paths") and not match_paths(f["file"], ex["paths"]):
                continue
            expires = parse_date(ex["expires"])
            if expires < today:
                key = (str(ref), str(ex["expires"]))
                if key not in expired_seen:
                    expired_seen.add(key)
                    notes.append("exception for '" + str(ref) + "' EXPIRED " +
                                 str(ex["expires"]) + " - enforcement restored")
                continue
            action = "ignore"
            f["exception"] = {
                "policy": str(ref),
                "reason": ex.get("reason", ""),
                "expires": str(ex["expires"]),
                "days_left": (expires - today).days,
            }

        f["action"] = action

    return [f for f in findings if f["action"] != "ignore"], notes


def exception_register(pol, today=None):
    """All declared exceptions with days-to-expiry, soonest first."""
    today = today or datetime.date.today()
    rows = []
    for ex in pol.get("exceptions") or []:
        expires = parse_date(ex["expires"])
        rows.append({
            "policy": str(ex.get("policy")),
            "paths": [str(p) for p in (ex.get("paths") or ["*"])],
            "reason": ex.get("reason", ""),
            "expires": str(ex["expires"]),
            "days_left": (expires - today).days,
            "expired": expires < today,
        })
    return sorted(rows, key=lambda r: r["days_left"])
