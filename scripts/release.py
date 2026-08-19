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
INCLUDE_DIRS = ["pqgate", "action", ".gitlab", "docs"]
INCLUDE_FILES = ["README.md", "LICENSE", "requirements.txt", "Makefile", "CLAUDE.md"]
EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", "cmvp-certificates.yml"}


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

    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(DIST)

    artifacts = [build_scanner(args.version), build_rules(args.version, args.unsigned)]

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
