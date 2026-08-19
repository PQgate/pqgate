#!/usr/bin/env python3
"""Build the release artifacts.

Shaped after aws-samples/amazon-eks-custom-amis: a public repository whose artifacts you
build and run inside your own boundary. AWS gives away the Packer recipe because the
value is EKS, not the template. Same logic here — discovery is the recipe, and the
things you cannot rebuild are current rule packs, refreshed CMVP data, and the Forge.

Produces, into dist/:

    pqgate-<version>.tar.gz          the scanner: CLI, rule packs, offline docs
    pqgate-<version>.tar.gz.sha256   checksum the GitHub Action verifies
    pqgate-rules-<version>.tar.gz    signed rule packs, installable on their own
    SHA256SUMS                           every artifact, one file

Everything here is offline. The release pipeline signs; the customer verifies.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from pqgate import VERSION  # noqa: E402

DIST = os.path.join(ROOT, "dist")

# What ships in the scanner tarball. Deliberately small: the scanner, its rules, the
# CI integrations and the docs someone needs on a machine with no browser.
INCLUDE_DIRS = ["pqgate", "action", ".gitlab"]
# The tarball is what a customer runs, not a development checkout. The Makefile drove
# targets whose files (tests/, scripts/) are not in it, and docs/ was shipped whole -
# which from the private tree would have packaged the roadmap and CLAUDE.md along with
# the scanner.
INCLUDE_FILES = ["README.md", "LICENSE", "requirements.txt",
                 "docs/sc-12-control-mapping.md"]
EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", "cmvp-certificates.yml"}

# Checked against every member of the built tarball. INCLUDE_* is the allowlist; this
# is the second lock, because a release is the one artifact that cannot be recalled.
FORBIDDEN_MEMBERS = ["CLAUDE.md", "docs/release-roadmap.md", "docs/pqgate-prototype",
                     "server/", "web/", "scripts/seed.py", "scripts/export_public.py",
                     ".pqgate-keys/", "SCREENS.md"]


def audit_tarball(path):
    """Refuse to publish a tarball containing anything private."""
    import tarfile as _tf
    bad = []
    with _tf.open(path) as tar:
        for member in tar.getnames():
            rel = member.split("/", 1)[1] if "/" in member else member
            for f in FORBIDDEN_MEMBERS:
                if rel == f or rel.startswith(f):
                    bad.append(rel)
    return bad


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _filter(info):
    base = os.path.basename(info.name)
    if base in EXCLUDE_NAMES or base.endswith(".pyc"):
        return None
    if "/__pycache__/" in info.name.replace(os.sep, "/"):
        return None
    # Reproducible-ish: strip owner metadata so two builds of the same tree match.
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def build_scanner(version):
    out = os.path.join(DIST, "pqgate-" + version + ".tar.gz")
    prefix = "pqgate-" + version
    with tarfile.open(out, "w:gz") as tar:
        for name in INCLUDE_DIRS:
            path = os.path.join(ROOT, name)
            if os.path.isdir(path):
                tar.add(path, arcname=prefix + "/" + name, filter=_filter)
        for name in INCLUDE_FILES:
            path = os.path.join(ROOT, name)
            if os.path.isfile(path):
                tar.add(path, arcname=prefix + "/" + name, filter=_filter)
    return out


def build_rules(version, unsigned=False):
    out = os.path.join(DIST, "pqgate-rules-" + version + ".tar.gz")
    cmd = [sys.executable, "-m", "pqgate", "packs-build", version, "--out", out]
    if unsigned:
        cmd.append("--unsigned")
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout + proc.stderr)
        raise SystemExit("rule pack build failed")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default=VERSION)
    ap.add_argument("--unsigned", action="store_true",
                    help="skip signing the rule pack bundle (no key available)")
    args = ap.parse_args()

    # Clear previous release artifacts only. dist/ also holds dist/public, the checkout
    # of the public repository - an rmtree here would take its .git with it, and a
    # release build has no business deleting a sibling repository.
    os.makedirs(DIST, exist_ok=True)
    for name in os.listdir(DIST):
        if name.startswith("pqgate-") or name == "SHA256SUMS":
            path = os.path.join(DIST, name)
            if os.path.isfile(path):
                os.remove(path)

    artifacts = [build_scanner(args.version), build_rules(args.version, args.unsigned)]
    for art in artifacts:
        leaked = audit_tarball(art)
        if leaked:
            print("\nRELEASE REFUSED - " + os.path.basename(art) + " contains:")
            for name in leaked:
                print("  " + name)
            return 1

    lines = []
    print("")
    for path in artifacts:
        digest = sha256(path)
        name = os.path.basename(path)
        with open(path + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(digest + "  " + name + "\n")
        lines.append(digest + "  " + name)
        print("  " + name.ljust(42) + str(os.path.getsize(path) // 1024).rjust(5) + " KB")
        print("    sha256:" + digest)

    with open(os.path.join(DIST, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("\n" + str(len(artifacts)) + " artifacts in dist/ for version " + args.version)
    print("The Action pins the scanner checksum; publish it with the release:")
    print("  checksum: " + sha256(artifacts[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
