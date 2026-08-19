"""OSS regression corpus: fetch, snapshot, and check.

    python scripts/corpus.py pin      # resolve each repo's current HEAD into corpus.yml
    python scripts/corpus.py fetch    # shallow-clone every repo at its pinned commit
    python scripts/corpus.py snapshot # record current findings as the expected baseline
    python scripts/corpus.py check    # fail on any regression, or FP rate >= 5%

`check` is the release gate from CLAUDE.md rule 4. It needs testdata/ populated by
`fetch`; without it the pytest wrapper skips rather than silently passing.
"""
import argparse
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from pqgate.outputs import rel  # noqa: E402
from pqgate.profiles import get_profile  # noqa: E402
from pqgate.scanner import scan_tree  # noqa: E402

CORPUS_YML = os.path.join(ROOT, "tests", "corpus", "corpus.yml")
SNAPSHOT_DIR = os.path.join(ROOT, "tests", "corpus", "snapshots")
TESTDATA = os.path.join(ROOT, "testdata")
FP_BUDGET = 0.05


def load_corpus():
    with open(CORPUS_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def save_corpus(doc):
    with open(CORPUS_YML, "w", encoding="utf-8") as fh:
        fh.write("# OSS regression corpus. Commits are pinned so results are reproducible;\n"
                 "# bumping a pin is a deliberate change that must ship with a snapshot update.\n"
                 "#\n"
                 "# expect: crypto - the repo genuinely contains cryptography; findings expected.\n"
                 "# expect: clean  - no cryptography of its own; any finding is a false positive\n"
                 "#                  against the <5% release gate.\n"
                 "# Regenerate pins with: python scripts/corpus.py pin\n")
        yaml.safe_dump(doc, fh, sort_keys=False, default_flow_style=False)


def run(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


# --------------------------------------------------------------------------
def cmd_pin(args):
    doc = load_corpus()
    for repo in doc["repos"]:
        ref = repo.get("ref", "HEAD")
        proc = run("git", "ls-remote", repo["url"], ref)
        if proc.returncode != 0 or not proc.stdout.strip():
            print("  " + repo["name"].ljust(20) + " FAILED to resolve " + ref)
            continue
        sha = proc.stdout.split()[0]
        repo["commit"] = sha
        print("  " + repo["name"].ljust(20) + " " + sha)
    save_corpus(doc)
    print("\npinned " + str(len(doc["repos"])) + " repos in " + CORPUS_YML)
    return 0


def cmd_fetch(args):
    doc = load_corpus()
    os.makedirs(TESTDATA, exist_ok=True)
    failures = []
    for repo in doc["repos"]:
        dest = os.path.join(TESTDATA, repo["name"])
        marker = os.path.join(dest, ".pqgate-pin")
        if os.path.exists(marker) and open(marker).read().strip() == repo["commit"] and not args.force:
            print("  " + repo["name"].ljust(20) + " cached")
            continue
        print("  " + repo["name"].ljust(20) + " fetching " + repo["commit"][:12] + " …")
        os.makedirs(dest, exist_ok=True)
        steps = [
            ("git", "init", "-q", dest),
            ("git", "-C", dest, "remote", "add", "origin", repo["url"]),
            ("git", "-C", dest, "fetch", "-q", "--depth", "1", "--filter=blob:none",
             "origin", repo["commit"]),
            ("git", "-C", dest, "checkout", "-q", "FETCH_HEAD"),
        ]
        ok = True
        for step in steps:
            proc = run(*step)
            if proc.returncode != 0 and "remote origin already exists" not in proc.stderr:
                print("      " + proc.stderr.strip().splitlines()[-1][:120])
                ok = False
                break
        if ok:
            with open(marker, "w") as fh:
                fh.write(repo["commit"])
        else:
            failures.append(repo["name"])
    if failures:
        print("\nfailed: " + ", ".join(failures))
        return 1
    print("\ncorpus ready in " + TESTDATA)
    return 0


def available(doc):
    out = []
    for repo in doc["repos"]:
        dest = os.path.join(TESTDATA, repo["name"])
        if os.path.exists(os.path.join(dest, ".pqgate-pin")):
            out.append((repo, dest))
    return out


def scan_repo(repo, dest, profile):
    findings = []
    for sub in repo.get("paths", ["."]):
        target = os.path.normpath(os.path.join(dest, sub))
        if not os.path.isdir(target):
            continue
        for f in scan_tree(target, profile):
            findings.append({
                "rule": f["rule"],
                "classification": f["classification"],
                "location": rel(f["file"], dest),
                "line": f["line"],
                "detector": f.get("detector", "regex"),
            })
    return sorted(findings, key=lambda f: (f["location"], f["line"], f["rule"]))


def cmd_snapshot(args):
    doc = load_corpus()
    profile = get_profile("cnsa-2.0")
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    pairs = available(doc)
    if not pairs:
        print("no corpus checkouts found — run: python scripts/corpus.py fetch")
        return 1
    for repo, dest in pairs:
        findings = scan_repo(repo, dest, profile)
        path = os.path.join(SNAPSHOT_DIR, repo["name"] + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"commit": repo["commit"], "expect": repo["expect"],
                       "findings": findings}, fh, indent=1)
        print("  " + repo["name"].ljust(20) + str(len(findings)).rjust(5) + " findings")
    return 0


def cmd_check(args):
    doc = load_corpus()
    profile = get_profile("cnsa-2.0")
    pairs = available(doc)
    if not pairs:
        print("no corpus checkouts found — run: python scripts/corpus.py fetch")
        return 1

    regressions, total, false_positives, gaps = [], 0, 0, []
    for repo, dest in pairs:
        findings = scan_repo(repo, dest, profile)
        total += len(findings)
        if repo["expect"] == "clean":
            false_positives += len(findings)
        if repo.get("known_gap") and not findings:
            gaps.append((repo["name"], repo["known_gap"]))

        snap_path = os.path.join(SNAPSHOT_DIR, repo["name"] + ".json")
        if not os.path.exists(snap_path):
            print("  " + repo["name"].ljust(20) + " NO SNAPSHOT (run snapshot)")
            regressions.append((repo["name"], "missing snapshot"))
            continue
        with open(snap_path, encoding="utf-8") as fh:
            snap = json.load(fh)
        if snap["commit"] != repo["commit"]:
            regressions.append((repo["name"], "snapshot is for a different pin"))
            continue

        def key(f):
            return (f["rule"], f["location"], f["line"])

        old, new = {key(f) for f in snap["findings"]}, {key(f) for f in findings}
        added, removed = new - old, old - new
        status = "ok"
        if added or removed:
            status = "+" + str(len(added)) + " / -" + str(len(removed))
            regressions.append((repo["name"], status))
        print("  " + repo["name"].ljust(20) + str(len(findings)).rjust(5) +
              " findings  " + status)

    rate = false_positives / total if total else 0.0
    print("\n" + str(len(pairs)) + " repos, " + str(total) + " findings, " +
          str(false_positives) + " false positives, FP rate " + str(round(rate * 100, 2)) + "%")
    if gaps:
        print("\nKNOWN COVERAGE GAPS (tracked, not failures):")
        for name, gap in gaps:
            print("  " + name + ": " + gap)

    failed = False
    if regressions:
        print("\nREGRESSIONS:")
        for name, what in regressions:
            print("  " + name + ": " + what)
        failed = True
    if rate >= FP_BUDGET:
        print("\nFP RATE " + str(round(rate * 100, 2)) + "% EXCEEDS THE " +
              str(int(FP_BUDGET * 100)) + "% RELEASE BUDGET")
        failed = True
    if failed:
        return 1
    print("corpus check passed")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="corpus")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pin").set_defaults(func=cmd_pin)
    f = sub.add_parser("fetch")
    f.add_argument("--force", action="store_true")
    f.set_defaults(func=cmd_fetch)
    sub.add_parser("snapshot").set_defaults(func=cmd_snapshot)
    sub.add_parser("check").set_defaults(func=cmd_check)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
