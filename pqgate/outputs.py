"""Artifacts: console, CBOM (CycloneDX 1.6), SARIF 2.1.0, CBOM diff, readiness report."""
import datetime
import hashlib
import json
import os

from . import VERSION

SEV = {"block": 3, "warn": 2, "pass": 1, "ignore": 0}
C = {"block": "\033[91m", "warn": "\033[93m", "pass": "\033[92m",
     "0": "\033[0m", "d": "\033[2m", "b": "\033[1m"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def canonical(doc):
    """Canonical JSON bytes used for every hash we publish."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash(doc):
    """SHA-384 over the CBOM content, recomputable by anyone.

    Both `metadata.contentHash` and `metadata.signature` are excluded. The hash covers
    the content; the signature is an envelope around it and covers the hash in turn.
    If the hash covered the signature too, the two would be circular and attaching a
    signature would invalidate the hash it was signing.
    """
    stripped = json.loads(json.dumps(doc))
    metadata = stripped.get("metadata", {})
    metadata.pop("contentHash", None)
    metadata.pop("signature", None)
    return "sha384:" + hashlib.sha384(canonical(stripped)).hexdigest()


def score(findings):
    scored = [f for f in findings if f["action"] in ("block", "warn", "pass")]
    if not scored:
        return 100
    return int(100 * sum(1 for f in scored if f["action"] == "pass") / len(scored))


# --------------------------------------------------------------------------
def console_report(findings, notes, root, profile, use_color=True):
    col = C if use_color else {k: "" for k in C}
    blocks = [f for f in findings if f["action"] == "block"]
    warns = [f for f in findings if f["action"] == "warn"]
    passes = [f for f in findings if f["action"] == "pass"]

    print("\n" + col["b"] + "PQgate v" + VERSION + col["0"] +
          " - profile: " + col["b"] + profile + col["0"] + "  target: " + str(root))
    print("-" * 74)
    for n in notes:
        print(" " + col["warn"] + "NOTE " + col["0"] + " " + n)
    for f in sorted(findings, key=lambda x: (-SEV[x["action"]], x["file"], x["line"])):
        c = col.get(f["action"], "")
        loc = f["file"] + ":" + str(f["line"]) if f["line"] else f["file"]
        det = f.get("detector", "regex")
        print(" " + c + f["action"].upper().ljust(5) + col["0"] + "  " + f["message"] +
              "  " + col["d"] + "(" + f["policy_id"] + " via " + det + ")" + col["0"])
        print("        " + col["d"] + loc + "  >  " + f["evidence"] + col["0"])
    print("-" * 74)
    print(" " + col["block"] + "block " + str(len(blocks)) + col["0"] +
          "   " + col["warn"] + "warn " + str(len(warns)) + col["0"] +
          "   " + col["pass"] + "pass " + str(len(passes)) + col["0"] +
          "   quantum-readiness score: " + col["b"] + str(score(findings)) + "/100" + col["0"])
    if blocks:
        print("\n " + col["block"] + "x GATE: BLOCKED" + col["0"] +
              " - " + str(len(blocks)) + " finding(s) violate policy\n")
    else:
        print("\n " + col["pass"] + "+ GATE: PASS" + col["0"] + "\n")
    return blocks, warns


# --------------------------------------------------------------------------
def rel(path, root):
    """Repo-relative, forward-slashed. Absolute paths would make every CI runner's
    CBOM diff against every other one."""
    try:
        out = os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        out = path
    return out.replace(os.sep, "/")


def build_cbom(findings, root, profile, exceptions=None, notes=None):
    comps = []
    for f in findings:
        comps.append({
            "type": "cryptographic-asset",
            "name": f["rule"],
            "evidence": {"occurrences": [{
                "location": rel(f["file"], root),
                "line": f["line"],
                "snippet": f["evidence"],
            }]},
            "cryptoProperties": {
                "classification": f["classification"],
                "detail": f["message"],
                "action": f["action"],
                "policy": f["policy_id"],
                "profile": profile,
                "detector": f.get("detector", "regex"),
                "controls": f.get("controls", []),
                "standards": f.get("standards", []),
                "remediation": f.get("remediation", ""),
            },
        })
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": now(),
            "tool": "pqgate/" + VERSION,
            "target": os.path.abspath(root).replace(os.sep, "/"),
            "profile": profile,
            "score": score(findings),
            "counts": {
                "block": sum(1 for f in findings if f["action"] == "block"),
                "warn": sum(1 for f in findings if f["action"] == "warn"),
                "pass": sum(1 for f in findings if f["action"] == "pass"),
            },
            "exceptions": exceptions or [],
            "notes": notes or [],
        },
        "components": comps,
    }
    doc["metadata"]["contentHash"] = content_hash(doc)
    return doc


def verify_cbom(doc):
    """True if the stored contentHash matches a recomputation."""
    stored = doc.get("metadata", {}).get("contentHash")
    return bool(stored) and stored == content_hash(doc)


# --------------------------------------------------------------------------
SARIF_LEVEL = {"block": "error", "warn": "warning", "pass": "note"}


def build_sarif(findings, root):
    rules, seen, results = [], set(), []
    for f in findings:
        if f["rule"] not in seen:
            seen.add(f["rule"])
            rules.append({
                "id": f["rule"],
                "name": f["rule"].replace("-", ""),
                "shortDescription": {"text": f["message"][:120]},
                "fullDescription": {"text": f["message"]},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(f["action"], "note")},
                "help": {"text": f.get("remediation") or
                                 "CNSA 2.0 requires ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384+. "
                                 "Replace the flagged primitive or file a policy exception with an expiry."},
                "properties": {
                    "classification": f["classification"],
                    "controls": f.get("controls", []),
                    "standards": f.get("standards", []),
                    "tags": ["cryptography", "pqc"] + sorted(f.get("controls", [])),
                },
            })
        uri = rel(f["file"], root)
        results.append({
            "ruleId": f["rule"],
            "level": SARIF_LEVEL.get(f["action"], "note"),
            "message": {"text": f["message"] + " [" + f["policy_id"] + "]"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(f["line"], 1)},
            }}],
            "partialFingerprints": {
                "pqgate/v1": hashlib.sha256(
                    (f["rule"] + "|" + uri + "|" + f["evidence"]).encode()).hexdigest()[:16]
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PQgate",
                "version": VERSION,
                "informationUri": "https://pqgate.example",
                "rules": rules,
            }},
            "results": results,
        }],
    }


# --------------------------------------------------------------------------
def cbom_delta(old_doc, new_doc):
    """Structured diff between two CBOMs. Used by the CLI, the Action and the web app."""
    def keyset(doc):
        out = {}
        for c in doc.get("components", []):
            occ = (c.get("evidence", {}).get("occurrences") or [{}])[0]
            key = (c["name"], occ.get("location", ""), c["cryptoProperties"]["classification"])
            out[key] = c
        return out

    o, n = keyset(old_doc), keyset(new_doc)
    added = [{"rule": k[0], "location": k[1], "classification": k[2],
              "action": n[k]["cryptoProperties"]["action"]} for k in sorted(n.keys() - o.keys())]
    removed = [{"rule": k[0], "location": k[1], "classification": k[2],
                "action": o[k]["cryptoProperties"]["action"]} for k in sorted(o.keys() - n.keys())]
    return {
        "added": added,
        "removed": removed,
        "score_from": old_doc.get("metadata", {}).get("score"),
        "score_to": new_doc.get("metadata", {}).get("score"),
    }


def print_cbom_diff(old_doc, new_doc, use_color=True):
    col = C if use_color else {k: "" for k in C}
    d = cbom_delta(old_doc, new_doc)
    print("\n" + col["b"] + "CBOM diff" + col["0"] + "  " +
          str(old_doc["metadata"]["timestamp"])[:19] + " -> " +
          str(new_doc["metadata"]["timestamp"])[:19])
    print(" score: " + str(d["score_from"]) + " -> " + str(d["score_to"]))
    for item in d["added"]:
        c = col["pass"] if item["classification"] == "pqc-safe" else col["block"]
        print(" " + c + "+ " + item["rule"] + col["0"] + "  " + col["d"] +
              item["location"] + " (" + item["classification"] + ")" + col["0"])
    for item in d["removed"]:
        c = col["block"] if item["classification"] == "pqc-safe" else col["pass"]
        print(" " + c + "- " + item["rule"] + col["0"] + "  " + col["d"] +
              item["location"] + " (" + item["classification"] + ")" + col["0"])
    if not d["added"] and not d["removed"]:
        print(" no cryptographic changes")
    print()
    return d


def markdown_diff(delta):
    lines = ["| | Asset | Location | Classification |", "|---|---|---|---|"]
    for item in delta["added"]:
        lines.append("| + | `" + item["rule"] + "` | `" + item["location"] + "` | " +
                     item["classification"] + " |")
    for item in delta["removed"]:
        lines.append("| - | `" + item["rule"] + "` | `" + item["location"] + "` | " +
                     item["classification"] + " |")
    if not delta["added"] and not delta["removed"]:
        lines = ["No cryptographic changes."]
    return "\n".join(lines)


# --------------------------------------------------------------------------
ATTESTATION_MARKER = "Report attestation (SHA-384 of report body):"

CONTROL_TITLES = {
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SA-11": "Developer Testing and Evaluation",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "CM-3": "Configuration Change Control",
    "IA-7": "Cryptographic Module Authentication",
}


def control_index(components):
    """Group CBOM components by the SP 800-53 control they are evidence for."""
    index = {}
    for c in components:
        props = c.get("cryptoProperties", {})
        for control in props.get("controls") or ["SC-13"]:
            entry = index.setdefault(control, {
                "control": control,
                "title": CONTROL_TITLES.get(control, ""),
                "standards": set(),
                "block": 0, "warn": 0, "pass": 0,
                "components": [],
            })
            entry["standards"].update(props.get("standards") or [])
            action = props.get("action", "warn")
            if action in entry:
                entry[action] += 1
            entry["components"].append(c)
    for entry in index.values():
        entry["standards"] = sorted(entry["standards"])
        entry["total"] = len(entry["components"])
    return index


def _control_section(components):
    """Per-control evidence table plus a detail block for each failing control."""
    index = control_index(components)
    if not index:
        return ["_No cryptographic assets detected, so no control evidence was produced._", ""]

    def occ(c):
        o = (c.get("evidence", {}).get("occurrences") or [{}])[0]
        return str(o.get("location", "-")) + ":" + str(o.get("line", 0))

    order = sorted(index.values(), key=lambda e: (-e["block"], -e["warn"], e["control"]))
    lines = ["| Control | Title | Assets | Blocking | Debt | Standards |", "|---|---|---|---|---|---|"]
    for e in order:
        lines.append("| **" + e["control"] + "** | " + e["title"] + " | " + str(e["total"]) +
                     " | " + str(e["block"]) + " | " + str(e["warn"]) + " | " +
                     (", ".join(e["standards"]) or "—") + " |")
    lines.append("")

    for e in order:
        failing = [c for c in e["components"]
                   if c["cryptoProperties"].get("action") in ("block", "warn")]
        if not failing:
            continue
        lines += ["### " + e["control"] + " — " + e["title"], ""]
        if e["standards"]:
            lines += ["Standards evidenced: " + ", ".join(e["standards"]), ""]
        for c in failing[:60]:
            props = c["cryptoProperties"]
            std = ", ".join(props.get("standards") or []) or props.get("classification", "")
            lines.append("- `" + occ(c) + "` — " + props["detail"] + "  [" + std + "]")
        lines.append("")
    return lines


def readiness_report_markdown(cbom, org):
    """CNSA 2.0 readiness report. Returns (markdown, attestation_hex)."""
    m = cbom["metadata"]
    comps = cbom.get("components", [])
    by_action = {}
    for c in comps:
        by_action.setdefault(c["cryptoProperties"]["action"], []).append(c)

    def occ(c):
        o = (c.get("evidence", {}).get("occurrences") or [{}])[0]
        return str(o.get("location", "-")) + ":" + str(o.get("line", 0))

    lines = [
        "# CNSA 2.0 Readiness Report",
        "",
        "**Organization:** " + org + "  ",
        "**Generated:** " + str(m["timestamp"]) + "  ",
        "**Profile:** " + str(m["profile"]) + "  *  **Tool:** " + str(m["tool"]) + "  ",
        "**Target:** `" + str(m["target"]) + "`",
        "",
        "## Posture Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        "| Quantum-readiness score | **" + str(m.get("score", "-")) + "/100** |",
        "| Blocking violations | " + str(len(by_action.get("block", []))) + " |",
        "| Migration debt (warnings) | " + str(len(by_action.get("warn", []))) + " |",
        "| Compliant assets | " + str(len(by_action.get("pass", []))) + " |",
        "| Total cryptographic assets | " + str(len(comps)) + " |",
        "",
        "## NIST SP 800-53 Control Coverage",
        "",
        "- **SC-13 (Cryptographic Protection):** the inventory below enumerates all detected",
        "  cryptographic mechanisms with per-asset compliance status against " + str(m["profile"]) + ".",
        "- **SC-12 (Cryptographic Key Establishment and Management):** key generation, key",
        "  establishment, module validation and key-lifecycle findings, evidenced against",
        "  FIPS 140-3 and the SP 800-56/57/133 series.",
        "- **SA-11 / RA-5:** findings are generated via automated static analysis on every build.",
        "- **CM-3:** exceptions are policy-tracked with mandatory expiry (see register below).",
        "",
    ]
    lines += _control_section(comps)
    lines += [
        "## Blocking Violations",
        "",
    ]
    if by_action.get("block"):
        for c in by_action["block"]:
            lines.append("- `" + occ(c) + "` - " + c["cryptoProperties"]["detail"])
    else:
        lines.append("- None.")

    lines += ["", "## Migration Debt (2033 full-transition tracking)", ""]
    if by_action.get("warn"):
        for c in by_action["warn"][:100]:
            lines.append("- `" + occ(c) + "` - " + c["cryptoProperties"]["detail"])
    else:
        lines.append("- None.")

    lines += ["", "## Exception Register", ""]
    excs = m.get("exceptions") or []
    if excs:
        lines += ["| Policy | Paths | Reason | Expires | Days left |", "|---|---|---|---|---|"]
        for e in excs:
            status = str(e["days_left"]) + (" (EXPIRED)" if e.get("expired") else "")
            lines.append("| `" + e["policy"] + "` | `" + ", ".join(e["paths"]) + "` | " +
                         e["reason"] + " | " + e["expires"] + " | " + status + " |")
    else:
        lines.append("- No policy exceptions declared.")

    lines += ["", "## Attestation", "", "CBOM content hash: `" + str(m.get("contentHash", "-")) + "`", ""]

    signature = m.get("signature")
    if signature:
        validated = signature.get("moduleValidated", False)
        lines += [
            "Evidence signature: `" + str(signature.get("algorithm", "?")) + "` (" +
            str(signature.get("standard", "?")) + ")",
            "",
            "| Field | Value |",
            "|---|---|",
            "| Signing key | `" + str(signature.get("keyFingerprint", "-")) + "` |",
            "| Signing module | `" + str(signature.get("module", "-")) + "` |",
            "| Module CMVP-validated | " + ("yes" if validated else "**no**") + " |",
            "",
        ]
        if not validated:
            lines += [
                "> The signing module is not CMVP-validated. The signature proves the "
                "evidence has not been altered since it was produced and identifies the "
                "key that produced it; it does not by itself satisfy a FIPS 140-3 "
                "requirement on the signing operation.",
                "",
            ]
        for note in signature.get("notes") or []:
            lines += ["> " + note, ""]
        lines += ["Verify the signature against a pinned key rather than the one embedded "
                  "in the document:", "", "    pqgate verify <cbom.json> --pubkey evidence.pub", ""]
    else:
        lines += ["Evidence signature: none. This report carries integrity (the hashes "
                  "below) but not authenticity - anyone can produce a document with a "
                  "correct self-consistent hash.", ""]

    body = "\n".join(lines)
    attestation = hashlib.sha384(body.encode("utf-8")).hexdigest()
    full = body + ATTESTATION_MARKER + " `sha384:" + attestation + "`\n"
    full += ("\n*Verification: recompute SHA-384 over the report body above this attestation line "
             "and compare; recompute the CBOM content hash over the CBOM with metadata.contentHash "
             "removed. Production releases sign this digest with the org's ML-DSA-87 "
             "report-signing key.*\n")
    return full, attestation


def verify_report(markdown_text):
    """Recompute the attestation over the report body. Returns (ok, expected, found)."""
    idx = markdown_text.find(ATTESTATION_MARKER)
    if idx < 0:
        return False, None, None
    body = markdown_text[:idx]
    expected = hashlib.sha384(body.encode("utf-8")).hexdigest()
    tail = markdown_text[idx:]
    found = tail.split("`sha384:")[1].split("`")[0] if "`sha384:" in tail else None
    return expected == found, expected, found


def readiness_report(cbom, org, out_path):
    text, _ = readiness_report_markdown(cbom, org)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return out_path
