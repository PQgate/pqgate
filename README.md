# PQgate

CNSA 2.0 crypto-compliance gate for CI/CD. Scans code, dependencies, configuration and
committed keys for quantum-vulnerable cryptography; verifies post-quantum parameter sets;
gates merges via policy-as-code; emits CycloneDX CBOMs, SARIF and signed readiness
reports.

**Free, permanently.** No account, no signup, and no license check anywhere on the scan
path. Clone it and run it.

Air-gap native: the scanner makes no network calls at all. The only one it can ever make
is an explicit `--push` to a server you name.

## Quick start

```bash
pip install pyyaml
python -m pqgate scan . --cbom cbom.json --sarif results.sarif
```

Or from a release, with the checksum verified first:

```bash
curl -fsSL -O https://github.com/PQgate/pqgate/releases/latest/download/pqgate-0.5.0.tar.gz
curl -fsSL -O https://github.com/PQgate/pqgate/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf pqgate-0.5.0.tar.gz
```

Exit codes: `0` pass · `1` gate blocked · `2` error — usable in any CI system.

## Gate a repository

Copy [`examples/github-actions.yml`](examples/github-actions.yml) to `.github/workflows/pqgate.yml`:

```yaml
name: Crypto Compliance Gate
on:
  pull_request:
  push: { branches: [main] }

jobs:
  pqgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # SARIF upload
      pull-requests: write     # sticky comment
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: PQgate/pqgate/action@v0.5.0
        with:
          fail-on: block
          checksum: <sha256 from the release SHA256SUMS>
```

Findings annotate the exact line in code scanning, and a `block` fails the required
check. One sticky comment shows the CBOM diff against the target branch.

GitLab: `include: { local: '.gitlab/pqgate.yml' }`.

## The finding most tools miss

```
WARN   PQC via liboqs - PQC present but below profile parameter set
       auth/kem.py:11  >  return oqs.KeyEncapsulation("ML-KEM-768")
```

The team migrated to post-quantum key establishment and it is still not CNSA 2.0,
because the suite requires ML-KEM-1024 and ML-DSA-87 — the Category 5 parameter sets
only. A scanner that reports "post-quantum cryptography detected" without resolving the
parameter set calls that compliant.

## Detection

| Layer | What | How |
|---|---|---|
| 1 | `requirements.txt`, `go.mod`, `pom.xml` | package knowledge base |
| 2 | Python source | **AST** — call targets resolved, string constants tracked to their use |
| 2 | Go, Java source | comment-stripped regex |
| 3 | Committed private keys and certificates | PEM header scan |
| 4 | nginx, sshd, java.security, openssl.cnf, Terraform | configuration and IaC |
| 5 | Cryptographic module validation | FIPS 140-3 / CMVP posture |

Layers 4 and 5 exist because SC-12 asks a different question from SC-13: not *which
algorithm did you pick* but *where did the key come from, in what validated module, and
what happens to it over its life*.

Rules live in `pqgate/rules/*.yml` as data — id, languages, pattern, optional AST
matcher, classification, controls, standards — so a rule pack ships without the engine.

## Policy file

```yaml
version: 1
profile: cnsa-2.0            # or cnsa-2.0-fips, fips-140-3, nist-baseline

policies:
  - id: no-new-rsa
    match: { algorithm: RSA }
    scope: new-code-only     # existing findings stay tracked debt
    action: block

exceptions:
  - policy: no-new-rsa
    paths: ["legacy/**"]
    reason: "Vendor constraint; ticket SEC-142"   # required
    expires: 2027-06-30                           # required

reporting:
  fail_build_on: block
```

Both `reason` and `expires` are mandatory and the policy fails to load without them.
There is no permanent exception, because a permanent exception is a policy change
wearing a disguise. Past the date, enforcement returns and the run says so.

## Evidence

Every scan produces a CBOM whose `metadata.contentHash` is SHA-384 over the canonical
document. Reports end with a SHA-384 attestation over their own body. Both recompute
from the downloaded files alone — no server, no network:

```bash
python -m pqgate keys generate
python -m pqgate keys trust .pqgate-keys/evidence.pub --name "Release Eng"
python -m pqgate scan . --cbom cbom.json --sign
python -m pqgate verify cbom.json --require-signed
```

Signatures are ML-DSA-87 (FIPS 204) and verified against a **pinned** key rather than
the one embedded in the document. An unpinned signature proves the document is
unaltered, not who produced it, and the tool never conflates the two.

PQgate implements no cryptographic algorithm. Primitives come from a pluggable backend,
and every signature records which module produced it and whether that module is
CMVP-validated.

## Commands

```
scan <path>    [--policy .pqgate.yml] [--profile NAME]
               [--cbom out.json] [--sarif out.sarif]
               [--diff-base origin/main] [--fail-on block|warn|never]
               [--sign] [--push URL --token TOK]
diff <old.json> <new.json>      report <cbom.json> --org NAME [--pdf out.pdf]
sign <cbom.json>                verify <artifact>... [--pubkey k.pub] [--require-signed]
keys generate|trust|list|backends
exceptions [path] [--json]      rules [--json]      profiles
controls [--json]               cmvp [status|import <file>]
packs                           packs-update <bundle> [--dry-run]
license [status|install <file>]
```

## Free, and what is not

Scanning never checks a license. A license gates rule-pack *updates* and the refreshed
CMVP feed — the packs you have keep working forever, and they go stale, because the
guidance underneath them moves. See [LICENSING.md](LICENSING.md).

**PQforge** — key management, LMS firmware signing and the TLS gateway — is a separate
product that is provisioned rather than downloaded. It holds key material, so there is
no tarball and there will not be one.

## Tests

```bash
make test           # scanner, policy engine, artifacts, signing, licensing
make corpus-fetch   # clone 10 pinned OSS repos into testdata/
make corpus-test    # regression + false-positive gate (<5% is a release blocker)
```

Current corpus result: 10 repos, 160 findings, **0 false positives**, with one tracked
coverage gap — Java algorithm names arriving as variables rather than string literals,
which the tree-sitter pass closes.

## Status

Prototype-grade in one specific way that matters: detection is pattern- and AST-based
Python. The production scanner is a single static Go binary with tree-sitter parsing,
and it is **not built yet**. This package is the behavioural contract for that port —
the test suite encodes the exact findings, exit codes, CBOM and SARIF shapes it must
reproduce.

See [RELEASE.md](RELEASE.md) for how releases are built and signed.
