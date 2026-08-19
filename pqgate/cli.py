"""PQgate CLI. Exit codes: 0 pass, 1 gate blocked, 2 error."""
import argparse
import json
import os
import sys

from . import EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, VERSION
from .outputs import (build_cbom, build_sarif, console_report, print_cbom_diff,
                      readiness_report, verify_cbom, verify_report)
from .policy import (PolicyError, apply_policy, exception_register, git_changed_files,
                     load_policy)
from .profiles import ProfileError, get_profile, load_profiles
from .rules import (CONTROL_TITLES, RuleSetError, all_rules, load_cmvp,
                    load_cmvp_overlay, save_cmvp_overlay)
from .scanner import scan_tree


def err(msg):
    print("pqgate: error: " + str(msg), file=sys.stderr)
    sys.exit(EXIT_ERROR)


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_policy(path_arg, target, profile, custom_dir):
    candidate = path_arg or os.path.join(target, ".pqgate.yml")
    return load_policy(candidate if os.path.exists(candidate) else None, profile, custom_dir)


# --------------------------------------------------------------------------
def cmd_scan(args):
    if not os.path.isdir(args.path):
        err("not a directory: " + args.path)
    pol = _resolve_policy(args.policy, args.path, args.profile, args.profiles_dir)
    profile = get_profile(pol["profile"], args.profiles_dir)

    changed = git_changed_files(args.path, args.diff_base) if args.diff_base else None
    findings = scan_tree(args.path, profile)
    findings, notes = apply_policy(findings, pol, changed_files=changed,
                                   custom_profile_dir=args.profiles_dir)
    register = exception_register(pol)

    # A stale rule pack is the one failure mode a scanner cannot report on itself:
    # it comes back clean. Say so, on every scan, and never let it change the verdict.
    from .rules import STALE_AFTER_DAYS, stale_packs
    stale = stale_packs()
    if stale:
        notes.append("rule pack(s) " + ", ".join(p["name"] for p in stale) +
                     " are more than " + str(STALE_AFTER_DAYS) + " days old - they still "
                     "work, but new rules are not present. See: pqgate packs")

    blocks, warns = console_report(findings, notes, args.path, pol["profile"],
                                   use_color=not args.no_color)

    cbom = build_cbom(findings, args.path, pol["profile"], exceptions=register, notes=notes)
    if args.cbom:
        with open(args.cbom, "w", encoding="utf-8") as fh:
            json.dump(cbom, fh, indent=2)
        print(" CBOM  -> " + args.cbom)
        if args.sign:
            # Sign before the push, so what reaches the evidence server is the signed
            # artifact and the server verifies exactly what was written to disk.
            from .cli_signing import sign_file
            from .signing import BackendUnavailable, SigningError
            from .signing.keystore import KeystoreError
            try:
                sign_file(args.cbom, args.signer, args.key_dir, profile=pol["profile"],
                          allow_unvalidated=args.allow_unvalidated_signer)
                cbom = _load(args.cbom)
            except (SigningError, BackendUnavailable, KeystoreError) as exc:
                err(exc)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(build_sarif(findings, args.path), fh, indent=2)
        print(" SARIF -> " + args.sarif)
    if args.push:
        from .push import push_cbom
        try:
            info = push_cbom(args.push, args.token, cbom, repo=args.repo,
                             branch=args.branch, commit=args.commit, org=args.org)
            print(" PUSH  -> " + args.push + " (scan #" + str(info.get("scan_id")) + ")")
        except Exception as exc:  # network/server errors must not mask the gate result
            print(" PUSH  -> FAILED: " + str(exc), file=sys.stderr)
    if args.cbom or args.sarif or args.push:
        print()

    fail_on = args.fail_on or pol.get("reporting", {}).get("fail_build_on", "block")
    if fail_on == "block" and blocks:
        return EXIT_BLOCKED
    if fail_on == "warn" and (blocks or warns):
        return EXIT_BLOCKED
    return EXIT_PASS


def cmd_diff(args):
    print_cbom_diff(_load(args.old), _load(args.new), use_color=not args.no_color)
    return EXIT_PASS


def cmd_report(args):
    cbom = _load(args.cbom)
    out = readiness_report(cbom, args.org, args.out)
    print("readiness report -> " + out)
    if args.pdf:
        from .pdf import render_pdf
        with open(out, encoding="utf-8") as fh:
            render_pdf(fh.read(), args.pdf, org=args.org)
        print("readiness PDF    -> " + args.pdf)
    return EXIT_PASS


def cmd_exceptions(args):
    pol = _resolve_policy(args.policy, args.path, None, args.profiles_dir)
    rows = exception_register(pol)
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_PASS
    if not rows:
        print("no exceptions declared")
        return EXIT_PASS
    print("")
    print("POLICY".ljust(22) + "EXPIRES".ljust(13) + "DAYS".rjust(6) + "  PATHS / REASON")
    print("-" * 78)
    for r in rows:
        status = "EXPIRED" if r["expired"] else str(r["days_left"])
        print(r["policy"].ljust(22) + r["expires"].ljust(13) + status.rjust(6) +
              "  " + ", ".join(r["paths"]))
        print(" " * 41 + r["reason"])
    print("")
    return EXIT_PASS


def cmd_verify(args):
    """Integrity (content hash / attestation) and, for CBOMs, authenticity (signature).

    An unsigned artifact is not a failure - most pipelines start that way - but an
    invalid signature is, and so is an unpinned one when --require-signed is set.
    """
    from .cli_signing import describe_signature
    from .signing.envelope import INVALID, UNSIGNED, VALID_PINNED

    ok = True
    for path in args.artifacts:
        if path.endswith(".md"):
            with open(path, encoding="utf-8") as fh:
                good, expected, found = verify_report(fh.read())
            print(("OK   " if good else "FAIL ") + path + "  attestation " +
                  (str(found)[:16] if found else "missing"))
            if not good:
                print("      expected sha384:" + str(expected))
            ok = ok and good
            continue

        doc = _load(path)
        good = verify_cbom(doc)
        print(("OK   " if good else "FAIL ") + path + "  " +
              str(doc.get("metadata", {}).get("contentHash", "no contentHash"))[:24])
        ok = ok and good

        status, line, extra = describe_signature(doc, args.pubkey)
        marker = "OK   " if status not in (INVALID,) else "FAIL "
        if args.require_signed and status != VALID_PINNED:
            marker = "FAIL "
        print("     " + marker.strip().ljust(5) + " " + line)
        for note in extra:
            print("           NOTE " + note)
        if status == INVALID:
            ok = False
        if args.require_signed and status != VALID_PINNED:
            ok = False
            if status == UNSIGNED:
                print("           --require-signed: unsigned evidence is not acceptable here")
    return EXIT_PASS if ok else EXIT_BLOCKED


def cmd_rules(args):
    rules = all_rules()
    if args.json:
        print(json.dumps([{"id": r.id, "langs": list(r.langs), "class": r.classification,
                           "message": r.message, "ast": bool(r.ast_calls)} for r in rules], indent=2))
        return EXIT_PASS
    print("")
    print("RULE".ljust(24) + "LANG".ljust(10) + "DETECTOR".ljust(10) + "CLASSIFICATION")
    print("-" * 78)
    for r in sorted(rules, key=lambda x: x.id):
        print(r.id.ljust(24) + ",".join(r.langs).ljust(10) +
              ("ast+regex" if r.ast_calls else "regex").ljust(10) + r.classification)
    print("\n" + str(len(rules)) + " rules loaded from pqgate/rules/source.yml\n")
    return EXIT_PASS


def cmd_controls(args):
    """What SP 800-53 controls the loaded rule set can produce evidence for."""
    coverage = {}
    for r in all_rules():
        for c in r.controls or ("SC-13",):
            entry = coverage.setdefault(c, {"rules": 0, "standards": set()})
            entry["rules"] += 1
            entry["standards"].update(r.standards)
    if args.json:
        print(json.dumps({c: {"title": CONTROL_TITLES.get(c, ""), "rules": v["rules"],
                              "standards": sorted(v["standards"])}
                          for c, v in coverage.items()}, indent=2))
        return EXIT_PASS
    print("")
    print("CONTROL".ljust(10) + "RULES".rjust(6) + "  TITLE")
    print("-" * 78)
    for c in sorted(coverage, key=lambda x: -coverage[x]["rules"]):
        v = coverage[c]
        print(c.ljust(10) + str(v["rules"]).rjust(6) + "  " + CONTROL_TITLES.get(c, ""))
        if v["standards"]:
            print(" " * 18 + ", ".join(sorted(v["standards"])))
    print("")
    return EXIT_PASS


def cmd_cmvp(args):
    """Cryptographic module posture, and import of the operator's own CMVP export."""
    if args.action == "import":
        with open(args.file, encoding="utf-8") as fh:
            doc = json.load(fh)
        records = doc.get("modules", doc) if isinstance(doc, dict) else doc
        overlay = {}
        if isinstance(records, dict):
            items = records.items()
        else:
            items = [(r.get("module") or r.get("id"), r) for r in records]
        for mid, rec in items:
            if not mid:
                continue
            overlay[mid] = {k: rec.get(k) for k in ("cert", "status", "sunset")
                            if rec.get(k) is not None}
        path = save_cmvp_overlay(overlay)
        print("imported " + str(len(overlay)) + " module certificate record(s) -> " + path)
        return EXIT_PASS

    modules = load_cmvp()
    imported = load_cmvp_overlay()
    if args.json:
        print(json.dumps(modules, indent=2, default=str))
        return EXIT_PASS
    print("")
    print("MODULE".ljust(24) + "VALIDATED".ljust(11) + "CERT".ljust(10) + "STATUS")
    print("-" * 78)
    for mid in sorted(modules):
        m = modules[mid]
        print(mid.ljust(24) + ("yes" if m["validated"] else "NO").ljust(11) +
              str(m.get("cert") or "-").ljust(10) + str(m.get("status") or "unverified"))
    if not imported:
        print("")
        print("No CMVP export imported: certificate status reads 'unverified' rather than")
        print("guessing. Import one with: pqgate cmvp import <validated-modules.json>")
    print("")
    return EXIT_PASS


def cmd_profiles(args):
    profiles = load_profiles(args.profiles_dir)
    for name in sorted(profiles):
        p = profiles[name]
        print(name + " - " + p.get("description", ""))
        for cls, action in sorted(p["actions"].items()):
            print("   " + cls.ljust(22) + action)
        print("")
    return EXIT_PASS


# --------------------------------------------------------------------------
def build_parser():
    # Flags accepted either before or after the subcommand. argparse would otherwise
    # let the subparser's default clobber a value given globally, so the shared copy
    # defaults to SUPPRESS and simply does not set the attribute when absent.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="disable ANSI colors")
    common.add_argument("--profiles-dir", default=argparse.SUPPRESS,
                        help="directory of custom profile YAML files")

    ap = argparse.ArgumentParser(prog="pqgate",
                                 description="CNSA 2.0 crypto-compliance gate")
    ap.add_argument("--version", action="version", version="pqgate " + VERSION)
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--profiles-dir", default=os.environ.get("PQGATE_PROFILES"),
                    help="directory of custom profile YAML files")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=argparse.ArgumentParser)

    _add_parser = sub.add_parser

    def add_parser(name, **kw):
        kw.setdefault("parents", [common])
        return _add_parser(name, **kw)

    sub.add_parser = add_parser

    s = sub.add_parser("scan", help="scan a directory and evaluate policy")
    s.add_argument("path")
    s.add_argument("--policy", default=None, help="path to .pqgate.yml (auto-detected in target)")
    s.add_argument("--profile", default=None, help="override profile")
    s.add_argument("--cbom", default=None, help="write CycloneDX 1.6 CBOM here")
    s.add_argument("--sarif", default=None, help="write SARIF 2.1.0 here")
    s.add_argument("--diff-base", default=None, help="git ref for new-code-only scoping")
    s.add_argument("--fail-on", default=None, choices=["block", "warn", "never"])
    s.add_argument("--push", default=None, help="evidence server base URL")
    s.add_argument("--token", default=os.environ.get("PQGATE_TOKEN"), help="server admin token")
    s.add_argument("--repo", default=None, help="repo name recorded with the pushed scan")
    s.add_argument("--branch", default=None)
    s.add_argument("--commit", default=None)
    s.add_argument("--org", default=os.environ.get("PQGATE_ORG"), help="organization recorded with the pushed scan")
    s.add_argument("--sign", action="store_true",
                   help="sign the CBOM with ML-DSA-87 before writing and pushing")
    s.add_argument("--signer", default=None, help="signing backend")
    s.add_argument("--key-dir", default=None, help="signing key directory")
    s.add_argument("--allow-unvalidated-signer", action="store_true")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("diff", help="diff two CBOM files")
    d.add_argument("old")
    d.add_argument("new")
    d.set_defaults(func=cmd_diff)

    r = sub.add_parser("report", help="generate signed readiness report from a CBOM")
    r.add_argument("cbom")
    r.add_argument("--org", default="Unnamed Organization")
    r.add_argument("--out", default="cnsa-readiness-report.md")
    r.add_argument("--pdf", default=None, help="also render a PDF here")
    r.set_defaults(func=cmd_report)

    e = sub.add_parser("exceptions", help="list policy exceptions by days-to-expiry")
    e.add_argument("path", nargs="?", default=".")
    e.add_argument("--policy", default=None)
    e.add_argument("--json", action="store_true")
    e.set_defaults(func=cmd_exceptions)

    v = sub.add_parser("verify", help="verify content hashes, attestations and signatures")
    v.add_argument("artifacts", nargs="+")
    v.add_argument("--pubkey", default=None,
                   help="verify against this pinned public key rather than the embedded one")
    v.add_argument("--require-signed", action="store_true",
                   help="fail unless every CBOM is signed by a pinned key")
    v.set_defaults(func=cmd_verify)

    from .cli_signing import cmd_keys, cmd_sign
    k = sub.add_parser("keys", help="signing keys and the trust store")
    k.add_argument("action", nargs="?", default="list",
                   choices=["list", "generate", "trust", "backends"])
    k.add_argument("file", nargs="?", help="public key file (for `trust`)")
    k.add_argument("--name", default=None, help="label for a pinned key")
    k.add_argument("--dir", default=None, help="key directory (default .pqgate-keys)")
    k.add_argument("--signer", default=None, help="signing backend")
    k.add_argument("--force", action="store_true", help="overwrite an existing key")
    k.add_argument("--json", action="store_true")
    k.set_defaults(func=cmd_keys)

    sg = sub.add_parser("sign", help="sign a CBOM with ML-DSA-87")
    sg.add_argument("file")
    sg.add_argument("--signer", default=None)
    sg.add_argument("--dir", default=None, help="key directory (default .pqgate-keys)")
    sg.add_argument("--profile", default=None,
                    help="profile the evidence claims to satisfy; FIPS profiles require "
                         "a validated signing module")
    sg.add_argument("--allow-unvalidated-signer", action="store_true")
    sg.set_defaults(func=cmd_sign)

    ru = sub.add_parser("rules", help="list loaded detection rules")
    ru.add_argument("--json", action="store_true")
    ru.set_defaults(func=cmd_rules)

    co = sub.add_parser("controls", help="SP 800-53 controls the rule set evidences")
    co.add_argument("--json", action="store_true")
    co.set_defaults(func=cmd_controls)

    cm = sub.add_parser("cmvp", help="cryptographic module validation posture")
    cm.add_argument("action", nargs="?", default="status", choices=["status", "import"])
    cm.add_argument("file", nargs="?", help="CMVP export JSON (for `import`)")
    cm.add_argument("--json", action="store_true")
    cm.set_defaults(func=cmd_cmvp)

    pr = sub.add_parser("profiles", help="list available compliance profiles")
    pr.set_defaults(func=cmd_profiles)

    from .cli_license import cmd_license, cmd_packs, cmd_packs_build, cmd_packs_update
    li = sub.add_parser("license", help="license status and installation")
    li.add_argument("action", nargs="?", default="status", choices=["status", "install"])
    li.add_argument("file", nargs="?", help="license.json (for `install`)")
    li.add_argument("--out", default=None, help="where to install it")
    li.add_argument("--json", action="store_true")
    li.set_defaults(func=cmd_license)

    pk = sub.add_parser("packs", help="installed rule packs and their age")
    pk.add_argument("--json", action="store_true")
    pk.set_defaults(func=cmd_packs)

    pb = sub.add_parser("packs-build", help="build a signed rule pack bundle (release tooling)")
    pb.add_argument("version")
    pb.add_argument("--out", default=None)
    pb.add_argument("--signer", default=None)
    pb.add_argument("--key-dir", default=None)
    pb.add_argument("--unsigned", action="store_true")
    pb.set_defaults(func=cmd_packs_build)

    pu = sub.add_parser("packs-update", help="install a signed rule pack bundle")
    pu.add_argument("bundle")
    pu.add_argument("--dry-run", action="store_true")
    pu.add_argument("--no-license-check", action="store_true",
                    help="install a bundle you built yourself")
    pu.set_defaults(func=cmd_packs_update)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (PolicyError, ProfileError, RuleSetError) as exc:
        err(exc)
    except FileNotFoundError as exc:
        err(exc)


if __name__ == "__main__":
    sys.exit(main())
