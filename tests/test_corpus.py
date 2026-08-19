"""OSS corpus regression gate (CLAUDE.md rule 4).

Skips when testdata/ has not been fetched, so the fast suite stays offline-friendly.
Populate it with: python scripts/corpus.py fetch
"""
import importlib.util
import os

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

spec = importlib.util.spec_from_file_location("corpus", os.path.join(ROOT, "scripts", "corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)

DOC = corpus.load_corpus()
PAIRS = corpus.available(DOC)

pytestmark = pytest.mark.skipif(
    not PAIRS, reason="corpus not fetched — run: python scripts/corpus.py fetch")


@pytest.fixture(scope="module")
def profile():
    from pqgate.profiles import get_profile
    return get_profile("cnsa-2.0")


@pytest.mark.parametrize("repo,dest", PAIRS, ids=[r["name"] for r, _ in PAIRS] or ["none"])
def test_no_regression_against_snapshot(repo, dest, profile):
    import json
    snap_path = os.path.join(corpus.SNAPSHOT_DIR, repo["name"] + ".json")
    assert os.path.exists(snap_path), "no snapshot — run: python scripts/corpus.py snapshot"
    with open(snap_path, encoding="utf-8") as fh:
        snap = json.load(fh)
    assert snap["commit"] == repo["commit"], "snapshot is for a different pinned commit"

    def key(f):
        return (f["rule"], f["location"], f["line"])

    old = {key(f) for f in snap["findings"]}
    new = {key(f) for f in corpus.scan_repo(repo, dest, profile)}
    assert new == old, {"added": sorted(new - old), "removed": sorted(old - new)}


def test_false_positive_rate_is_within_budget(profile):
    total = fp = 0
    for repo, dest in PAIRS:
        findings = corpus.scan_repo(repo, dest, profile)
        total += len(findings)
        if repo["expect"] == "clean":
            fp += len(findings)
    rate = fp / total if total else 0.0
    assert rate < corpus.FP_BUDGET, "FP rate " + str(round(rate * 100, 2)) + "% over budget"


def test_crypto_repos_actually_produce_findings(profile):
    """A rule pack that stops detecting anything would otherwise pass silently."""
    silent = []
    for repo, dest in PAIRS:
        if repo["expect"] != "crypto" or repo.get("known_gap"):
            continue
        if not corpus.scan_repo(repo, dest, profile):
            silent.append(repo["name"])
    assert not silent, "crypto repos with zero findings: " + str(silent)
