# Releasing

Shaped after [aws-samples/amazon-eks-custom-amis](https://github.com/aws-samples/amazon-eks-custom-amis):
a public repository whose artifacts you build and run inside your own boundary. AWS
publishes the Packer recipe because the value is EKS, not the template. Here the recipe
is discovery, and the things a fork does not obtain are the rule-pack refresh, the CMVP
feed and PQforge.

## What a release contains

| Artifact | What it is |
|---|---|
| `pqgate-<version>.tar.gz` | The scanner: CLI, rule packs, CI integrations, offline docs |
| `pqgate-rules-<version>.tar.gz` | Rule packs alone, signed, installable on their own |
| `SHA256SUMS` | Every artifact, one file |
| `*.sha256` | Per-artifact checksum, for `sha256sum -c` |

Nothing in a release phones home, and nothing in it needs a license to run.

## Cutting one

```bash
git tag v0.6.0
git push origin v0.6.0
```

The `Release` workflow then runs the full test suite, self-scans the packages we ship
with our own gate, builds the artifacts, and publishes them with generated notes. A
release that cannot pass its own gate does not ship.

Locally, to see exactly what the pipeline produces:

```bash
make release            # signed, if a signing key is present
make release-unsigned   # no key available
```

## Signing

Rule-pack bundles are signed with ML-DSA-87. The release workflow reads the key from two
repository secrets:

| Secret | Contents |
|---|---|
| `PQGATE_SIGNING_KEY` | base64 of the private key |
| `PQGATE_SIGNING_PUB` | base64 of the public key |

Without them the bundle builds **unsigned and says so**, rather than shipping something
that looks signed. `pqgate packs-update` prints a note for an unsigned bundle and
refuses one whose digests do not match.

Two things to fix before this is a real signing story:

1. The default backend is `dilithium-py`, which is unaudited pure Python. Our own scanner
   flags it and the FIPS profiles refuse it. Move release signing to liboqs with the
   native library, or to a PKCS#11 token, before publishing anything customers rely on.
2. `LICENSE_PUBLIC_KEY_B64` in `pqgate/license.py` is empty. Until a release key
   exists, license verification reports "no license-signing public key is bundled"
   instead of pretending to verify. Fill it in from the release key at the same time.

## Versioning

`pqgate/__init__.py` holds `VERSION` and everything reads it — the CBOM `tool` field,
the SARIF driver, the release filenames and the web footer. Bump it in the same commit as
the tag.

Rule packs carry their own dates in each pack's `pack:` block, independent of the product
version, because a rules-only release is a normal thing to cut.

## Checklist

- [ ] `make test` — full suite
- [ ] `make corpus-test` — regression and false-positive gate
- [ ] `make linkcheck` — every route and internal link resolves
- [ ] Self-scan clean on `pqgate`, `server/pqgate_server`, `action`
- [ ] `VERSION` bumped
- [ ] Rule pack `released:` dates updated if rules changed
- [ ] `docs/release-roadmap.md` updated
- [ ] Tag pushed; artifacts and `SHA256SUMS` attached to the GitHub release
- [ ] Action example in `/quickstart` updated with the new checksum

## What is not in the repository, deliberately

- **CMVP certificate data.** Time-sensitive and authoritative only in CMVP's own export.
  Bundling a stale copy would let the tool assert that a lapsed certificate is current —
  the precise failure the feature exists to prevent.
- **Any signing key.** `.pqgate-keys/` is gitignored. The trust store
  (`.pqgate/trusted-keys.yml`) *is* tracked, because adding a key that can sign your
  evidence should go through review.
- **PQforge.** Not a downloadable artifact and will not become one. See `LICENSING.md`.
