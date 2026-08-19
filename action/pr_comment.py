"""Post or update the single sticky PQgate comment on a pull request.

The marker comment is found by an HTML sentinel, so repeated pushes edit one comment
instead of burying the PR. Only ever talks to the configured GitHub API host.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqgate.outputs import cbom_delta, markdown_diff  # noqa: E402

MARKER = "<!-- pqgate-sticky-comment -->"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def gh(path, method="GET", body=None, token=None):
    req = urllib.request.Request(
        API.rstrip("/") + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + (token or ""),
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode() or "{}")


def verdict(meta):
    counts = meta.get("counts", {})
    if counts.get("block"):
        return ("### PQgate — gate BLOCKED\n\n"
                + str(counts["block"]) + " finding(s) violate the "
                + str(meta.get("profile")) + " policy.")
    return "### PQgate — gate passed\n\nNo blocking violations against " + \
           str(meta.get("profile")) + "."


def build_body(cbom, baseline):
    meta = cbom.get("metadata", {})
    counts = meta.get("counts", {})
    lines = [
        MARKER,
        verdict(meta),
        "",
        "| Metric | Value |",
        "|---|---|",
        "| Quantum-readiness score | **" + str(meta.get("score")) + "/100** |",
        "| Blocking violations | " + str(counts.get("block", 0)) + " |",
        "| Migration debt | " + str(counts.get("warn", 0)) + " |",
        "| Compliant assets | " + str(counts.get("pass", 0)) + " |",
        "",
    ]
    if baseline:
        delta = cbom_delta(baseline, cbom)
        lines += [
            "#### Cryptographic changes in this PR",
            "",
            "score " + str(delta["score_from"]) + " -> " + str(delta["score_to"]),
            "",
            markdown_diff(delta),
            "",
        ]
    exceptions = meta.get("exceptions") or []
    expiring = [e for e in exceptions if e.get("expired") or e.get("days_left", 999) <= 30]
    if expiring:
        lines += ["#### Exceptions needing attention", ""]
        for e in expiring:
            state = "EXPIRED" if e.get("expired") else str(e["days_left"]) + " days left"
            lines.append("- `" + e["policy"] + "` (" + state + ") — " + e["reason"])
        lines.append("")
    lines += [
        "<sub>CBOM content hash `" + str(meta.get("contentHash", ""))[:32] + "…` · "
        "full CBOM and SARIF are attached to this run as artifacts.</sub>",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cbom", required=True)
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--repo", required=True, help="owner/name")
    ap.add_argument("--pr", required=True)
    ap.add_argument("--token", default=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    ap.add_argument("--dry-run", action="store_true", help="print the comment, post nothing")
    args = ap.parse_args()

    with open(args.cbom, encoding="utf-8") as fh:
        cbom = json.load(fh)
    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, encoding="utf-8") as fh:
            baseline = json.load(fh)

    body = build_body(cbom, baseline)
    if args.dry_run:
        print(body)
        return 0

    base = "/repos/" + args.repo + "/issues/" + str(args.pr)
    try:
        existing = gh(base + "/comments?per_page=100", token=args.token)
        mine = next((c for c in existing if MARKER in (c.get("body") or "")), None)
        if mine:
            gh("/repos/" + args.repo + "/issues/comments/" + str(mine["id"]),
               method="PATCH", body={"body": body}, token=args.token)
            print("updated sticky comment " + str(mine["id"]))
        else:
            created = gh(base + "/comments", method="POST", body={"body": body}, token=args.token)
            print("created sticky comment " + str(created.get("id")))
    except urllib.error.HTTPError as exc:
        # A comment failure must never mask the gate result.
        print("::warning::could not post PR comment: HTTP " + str(exc.code), file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
