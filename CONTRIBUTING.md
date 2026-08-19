# Contributing

The most useful contribution is a **detection rule**, and the second most useful is a
**false positive**.

## Reporting a false positive

A rule that fires on correct code is a defect, and we treat it as one. Open an issue
with the smallest snippet that triggers it and the rule id from the output. False
positives are a release blocker: the corpus gate fails the build at or above 5%.

## Adding a rule

Rules are data. No engine changes required for most of them.

1. Add an entry to the right pack in `pqgate/rules/` — `source.yml` for algorithm
   detection, `keygen.yml` for SP 800-133, `keyestab.yml` for SP 800-56, `config.yml`
   for configuration files, `iac.yml` for infrastructure-as-code.
2. Every rule needs an id, a language or filename glob, a pattern, a classification, a
   message, and — for anything in the SC-12 classes — a `controls` list. Loading fails
   without them.
3. Add a positive fixture in `tests/test_rules.py` or `tests/test_rules_sc12.py`. A rule
   with no fixture fails the suite.
4. Add a negative fixture if the rule could plausibly fire on correct code. This is the
   part that keeps the tool usable.
5. Run `make test`, then `make corpus-fetch && make corpus-test`. The corpus tells you
   what your rule does to ten real codebases, which is information no amount of
   reasoning substitutes for.

## Things we will not merge

- **Cryptographic implementations.** PQgate implements no algorithm and never will.
  Primitives come from audited libraries through the `Signer` interface. Interfaces yes,
  algorithms never.
- **Anything that phones home.** No telemetry, no usage beacon, no license check on the
  scan path. Every feature must work fully offline.
- **A rule with no test**, or a rule that raises the corpus false-positive rate.
- **Bundled CMVP certificate data.** It goes stale, and stale certificate data lets the
  tool assert that a lapsed certificate is current — the exact failure the feature
  exists to prevent.

## Standards accuracy

Content about CNSA 2.0, FIPS 203/204/205, SP 800-56, SP 800-57, SP 800-133 or SP 800-208
must trace to the published standard. If a claim cannot be sourced, it does not ship.
Corrections to existing content are welcome and will be merged quickly.
