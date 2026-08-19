# SC-12 control mapping

How PQgate produces evidence for **SC-12 — Cryptographic Key Establishment and
Management**, and the four standards that define what SC-12 actually requires.

## Why this is a separate axis

Until this release, every rule answered one question: *which algorithm did you pick?*
That is SC-13. SC-12 asks a different one: *where did the key come from, how was it
agreed, inside what validated module, and what happens to it over its life?*

The two are independent. A FIPS 140-3 validated module can happily generate RSA keys —
validated and quantum-vulnerable. A CNSA 2.0 compliant codebase can generate ML-KEM-1024
keys from `random.randint` — right algorithm, worthless key. Neither scan catches the
other's failure, which is why every rule now carries a `controls` list and profiles can
select on it.

Before this release, a tree containing a key from a non-approved RBG, a hardcoded AES
key, PKCS#1 v1.5 encryption, a raw ECDH secret, non-FIPS BouncyCastle and a KMS key with
rotation disabled scored **100/100 and passed the gate**. That was the gap.

## The rule schema

```yaml
- id: py-keygen-weak-rbg
  class: keygen-not-approved       # what kind of problem (profile decides the action)
  controls: [SC-12, SC-13]         # which controls this is evidence for
  standards: ["SP 800-133", "SP 800-90A"]
  remediation: Use secrets.token_bytes() or os.urandom().
  key_context: true                # only fire when the value is used as key material
```

`controls` is validated on load against a known list, and any rule in an SC-12
classification must declare at least one control — a rule that produces evidence for
nothing is a bug.

## The four standards

### FIPS 140-2 / 140-3 (CMVP) — `module-not-validated`, `module-cert-historical`

Detected from the dependency manifest, resolved through `pqgate/rules/cmvp.yml`.
The durable fact is *which distribution* of a library is the validated module:

| Shipped | Validated module | Verdict |
|---|---|---|
| `bcprov` | `bc-fips` (BC-FJA) | not validated |
| OpenSSL without the FIPS provider | OpenSSL FIPS Provider | not validated |
| stock Go crypto | FIPS-enabled Go build | not validated |
| `pyca/cryptography` | the OpenSSL provider underneath it | not itself validated |
| `liboqs` | — | correct algorithms, no validation |

**Certificate numbers and sunset dates are deliberately not bundled.** They change
continuously and are authoritative only in CMVP's own export. A stale bundled copy would
let PQgate assert that a lapsed certificate is current — the precise failure this
feature exists to prevent. Until an export is imported, a validated distribution reports
`unverified` rather than claiming a certificate:

```
pqgate cmvp import validated-modules.json
pqgate cmvp                      # posture, with certificate status
```

The import writes `pqgate/rules/cmvp-certificates.yml`, which is gitignored.

Timing note worth carrying into a customer conversation: CMVP stopped accepting new
FIPS 140-2 submissions in September 2021, and 140-2 certificates move to the historical
list five years after validation. Check your own certificates against the current CMVP
list — an ATO citing a 140-2 certificate may already be resting on a historical one.

### SP 800-56A / 56B / 56C — `keyestab-not-approved`

Bright-line rules; the scheme is either on the approved list or it is not.

| Finding | Standard |
|---|---|
| RSA PKCS#1 v1.5 used for encryption | SP 800-56B — not an approved key-transport scheme |
| ECDH shared secret used without an approved KDF | SP 800-56A / 56C |
| Finite-field DH shared secret without a KDF | SP 800-56A / 56C |
| Static key reuse in an ephemeral scheme | SP 800-56A |

### SP 800-57 — `keymgmt-no-rotation`, `keymgmt-below-strength`

Crypto periods, rotation and key strength are operational, and in a modern estate they
are declared in infrastructure-as-code. That makes them statically checkable: KMS
rotation disabled, classical CMK specs, deprecated load-balancer TLS policies, secrets
inlined in state-tracked files, JKS keystores.

### SP 800-133 (with SP 800-90A) — `keygen-not-approved`, `keygen-hardcoded`

The highest-confidence findings in the tool: key material from a non-approved RBG,
deterministically seeded generators, hardcoded keys and IVs, password-based derivation
outside SP 800-132.

**Precision matters here.** Naively flagging every `random.*` call makes every temporary
filename in every CLI library an SP 800-133 violation — measured directly on the corpus,
that produced a false positive in `click`. RNG rules are therefore gated on *key
context*: the enclosing function name or assignment target must contain a key-related
token. Matching is on identifier tokens rather than substrings, so `iv` does not fire on
`private` and `mac` does not fire on `machine`.

## Profiles

| Profile | Purpose |
|---|---|
| `cnsa-2.0` | Algorithms. Module validation is advisory. |
| `fips-140-3` | SC-12. Unvalidated modules, weak key generation and unapproved key establishment all block; quantum-vulnerable algorithms are advisory. |
| `cnsa-2.0-fips` | Both, for programmes that need CNSA 2.0 algorithms inside a validated boundary. |
| `nist-baseline` | Permissive baseline. |

## Report output

The readiness report gains a **NIST SP 800-53 Control Coverage** section: a table of
every control with asset, blocking and debt counts and the standards evidenced, followed
by a per-control detail block listing each failing asset with its standard. That section
is inside the attestation body, so it is covered by the report's SHA-384 hash.

## What a scanner cannot prove

800-57 lifecycle and 800-133 generation are ultimately *operational*. Static analysis can
prove a key was generated badly; it cannot prove that rotation happens on schedule or
that generation occurred inside a validated boundary. That is the boundary where
PQforge takes over — Gate produces the SC-12 finding, Forge is the remediation that
closes it, and the same control moves from failing to satisfied in the report.
