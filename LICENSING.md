# Licensing model

Two products, two very different distribution models. The split is deliberate and it is
enforced by what each thing *is*, not by obfuscation.

## PQgate — discovery. Free, public, self-serve.

Anyone can clone the repository, run the scanner, and gate their pipelines. No account,
no signup, no license check anywhere on the scan path. This is the same posture as
[aws-samples/amazon-eks-custom-amis](https://github.com/aws-samples/amazon-eks-custom-amis):
the recipe is public because the value is not the recipe.

Everything in this repository is the free tier. There is no paid edition of the
scanner and no feature held back from it.

**Free, permanently, with no license installed:**

- Scanning at every layer, with the rule packs you have
- Every compliance profile that ships with the release
- CBOM, SARIF and readiness reports
- Evidence signing and verification
- Importing your own CMVP export
- The GitHub Action and the GitLab template

**A license gates updates, not use:**

| Entitlement | What it grants |
|---|---|
| `rules:update` | Install newer signed rule packs |
| `cmvp:refresh` | Refreshed CMVP certificate data from our feed |
| `profiles:custom` | Vendor-maintained compliance profiles |
| `evidence:api` | Evidence API and assessor portal links |
| `support` | A named support contact |

The packs you downloaded keep working forever. They also go stale, because the guidance
underneath them moves — and a stale rule pack is the one failure mode a scanner cannot
report on itself, since it comes back clean. Every scan therefore prints a NOTE once a
pack passes 90 days, and `pqgate packs` shows the age of each one.

That is the whole subscription argument, and it is an honest one. We are not selling
access to software you already have; we are selling the fact that CNSA guidance, library
ecosystems and CMVP certificate status all keep moving.

```bash
pqgate license            # status, entitlements, and what is free
pqgate packs              # installed packs and their age
pqgate packs-update b.tar.gz --dry-run   # inspect a bundle without a license
```

License files are signed with ML-DSA-87 and verified **offline** against a public key
bundled in the release. An air-gapped customer must be able to prove entitlement on a
machine that will never reach us, so there is no activation call and never will be.

## The platform — hosted, and not in this repository

The evidence server, the organisation dashboard, readiness trends across repositories,
the exception register as a managed view and the assessor portal are the hosted product.
They are not part of this repository and are not a licensed unlock of anything in it —
the scanner is complete on its own, and produces evidence you can read, diff and verify
with nothing but the files it wrote.

## PQforge — key management. Provisioned by us.

Forge is not self-serve and will not be. It holds key material, issues datakeys, signs
firmware with stateful LMS trees and keeps an append-only audit chain. Handing someone a
tarball that manages their signing state would be irresponsible: LMS index reuse is
catastrophic and unrecoverable, and the controls that prevent it are operational, not
textual.

To get Forge you contact us and we stand up the account — hosted, or single-tenant
inside your own boundary. There is no download link, and the absence of one is a feature.

## Why we are not trying to stop you reading the code

There is no mechanism that lets code execute on your runner while preventing you from
reading it. A GitHub Action is checked out onto your machine; a container image can be
unpacked. Any vendor claiming otherwise is describing an inconvenience, not a control.

The option that *would* protect the source — running scans on our servers — requires
your code to leave your boundary, which is the opposite of what this product is for.

So we do the legible thing instead. In this market, inspectable source is an asset: a
tool that runs inside an accreditation boundary and cannot be read is a hard sell, and
some customers require escrow outright. License enforcement here is a procurement
control, not a technical one. A defense contractor does not pirate tooling; their
compliance office will not allow it.

## The open-source license itself

**Decision required before the repository is published.** This file describes the
commercial model; it is not the software license, and no `LICENSE` file has been
committed, because a hand-transcribed legal text with an error in it is a real liability.

Two defensible choices:

- **Apache-2.0** — permissive, includes an explicit patent grant, and the most credible
  option for defense customers whose policies distinguish OSI-approved licenses from
  "source available". Maximises adoption and therefore the funnel. A competitor may
  legally fork the scanner and compete; in practice the moat is the rule-pack refresh,
  the CMVP feed and Forge, none of which a fork obtains.
- **Business Source License 1.1** — source-available with a change date. Prevents a
  competitor from offering the scanner as a hosted service until the license converts.
  Costs you some procurement conversations, because BSL is not OSI-approved and some
  policies treat that as disqualifying.

Recommendation: **Apache-2.0.** The thing you are protecting is not copyable by reading
the source, and in this market the credibility of a real open-source license is worth
more than the theoretical protection BSL provides.

Drop the canonical text from the chosen license into `LICENSE` before publishing.
