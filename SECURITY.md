# Security

The `fegrid-iec60870` project takes security seriously. This document explains how
to report a vulnerability privately, what versions are supported, and how we
disclose and acknowledge reports.

## Reporting a vulnerability

### Preferred: GitHub private vulnerability reporting

Use [GitHub Security Advisories][ghsa] to file a **private** report against
this repository. Private reports are visible only to the maintainers until a
fix is published.

[ghsa]: https://github.com/fegrid/iec60870/security/advisories/new

1. Open the link above.
2. Title the advisory with a short summary (e.g. "Link FSM accepts malformed
   confirm with arbitrary FIR/FIN").
3. Describe impact, affected versions, reproduction steps, and any proposed
   mitigation.
4. A maintainer will acknowledge within **3 business days**.

If GitHub private reporting is unavailable in this repository, fall back to
e-mail (see below). Do **not** open a public issue.

### Fallback: e-mail

Send reports to **<security contact — TBD>**. Encrypt sensitive details if
possible; PGP key, when published, will be linked from this section.

## What to include

A good report contains:

- The exact affected crate(s) and version(s).
- A reproduction: minimal code, capture, or pcap.
- Impact: crash, panic, memory unsafety, denial of service, authentication
  bypass, etc.
- Whether the report has been disclosed elsewhere.

## Supported versions

Security fixes are backported to the most recent minor of the published
runtime crates only:

| Version | Supported |
| ------- | --------- |
| latest `0.x` minor (`main`) | yes |
| older `0.x` minors          | best-effort, only if the fix is small and the regression risk is low |

Once the project reaches `1.0`, the support window will expand to the latest
released minor and the previous minor. Anything older is unsupported.

The three internal-only crates (`fegrid-iec60870-tools`, `-conformance`,
`-fixtures`, `-codegen`) are **not** supported for security reports. They are
not published and are consumed only inside this workspace.

## Disclosure timeline

We aim to follow a coordinated disclosure timeline of **90 days** from the
initial acknowledgement, regardless of release status. Concrete milestones:

- **T+3 business days** — acknowledgement and triage.
- **T+30 days** — proposed fix and CVE request (if applicable).
- **T+90 days** — public disclosure and advisory publication, or a written
  extension request with reasoning.

We will negotiate an extension with the reporter if a fix requires more time.

## Advisories and CVEs

Critical and high-impact issues will be published as GitHub Security
Advisories with an associated CVE. The advisory text will credit the
reporter (unless they ask to remain anonymous) and document the affected
versions, the fix version, and any workaround.

## Acknowledgements

Researchers and reporters who follow this policy will be credited in the
release notes of the fix and (with their consent) in a
`SecurityAcknowledgements` section of this document. Hall of fame, when
populated, will be appended below.

---

### SecurityAcknowledgements

_Empty — be the first._

