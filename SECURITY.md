# Security Policy

## Supported versions

| Version | Supported with security fixes |
| ------- | ----------------------------- |
| 0.1.x   | Yes — the current release line |
| < 0.1.0 | No — no earlier release exists |

AgentShield is at v0.1.0, a reference implementation. Only the latest
0.1.x release receives fixes. If you are running an older checkout,
update to the latest commit on the default branch first and check
whether the issue still reproduces there before reporting it.

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Email the
maintainer privately with:

- a description of the issue and its impact,
- steps to reproduce (policy file + call sequence if applicable),
- any suggested fix.

You will receive an acknowledgement, and the issue will be fixed and
disclosed after a fix is available.

### How to report

1. **Do not open a public issue, pull request, or discussion** for the
   vulnerability, and do not post a proof of concept publicly. A
   public report gives attackers the same information as defenders,
   before a fix exists.
2. Email the maintainer privately with:
   - a description of the issue and its impact — what an attacker
     gains, and what policy guarantee is broken (for example, a call
     that should be denied is allowed, an approval covers different
     arguments than the one approved, or a secret reaches the audit
     log unredacted);
   - the version or commit you tested against, and your Python version;
   - steps to reproduce (policy file + call sequence if applicable),
     ideally as a minimal policy and a minimal test case;
   - any suggested fix, if you have one.
3. **Do not include real secrets or real production data** in the
   report. Use the demo secret or an obviously fake value, and a
   scratch workspace.
4. Keep the report private until the fix is released and disclosed.
   If you need to discuss the issue with anyone else first (for
   example, your employer), say so in the report.

### What happens next

- **Acknowledgement:** within 7 days of the report, confirming
  receipt and whether the issue looks in scope.
- **Assessment:** the maintainers reproduce the issue against the
  latest release and decide severity, guided by the threat model in
  [THREAT_MODEL.md](THREAT_MODEL.md) — a break of a stated guarantee
  (default deny, deny-wins, approval binding, secret scoping/redaction,
  budget enforcement, audit completeness) is treated as serious; a
  break of something the threat model explicitly says the gateway does
  *not* protect against is recorded as a known limitation, not a
  vulnerability.
- **Fix:** a fix is prepared privately, with a regression test, and
  released as a patch version with a changelog entry. The reporter is
  credited in the release notes unless they ask not to be.
- **Disclosure:** after the fix is available, the issue is disclosed
  publicly (advisory and/or changelog entry) with the affected
  versions, the impact, and the fix. The target is disclosure within
  90 days of the report, sooner for severe issues; if that slips, the
  reporter will be told why.
- If the report is a duplicate, a known limitation, or out of scope,
  the maintainers will say so and point to the relevant part of the
  threat model — a report handled this way is not held against the
  reporter.

### Good-faith research

Good-faith security research against this repository is welcome. Do
not access, modify, or delete other people's data, do not run the
gateway against production systems or real secrets, and do not use
automated scanning that degrades shared infrastructure. The project
does not operate a bug-bounty programme.

## Scope

In scope: the policy engine, gateway check order, approval binding, secret
broker/redaction, budget enforcement, and audit log integrity in this
repository.

Out of scope (known limitations, see THREAT_MODEL.md): compromise of the
host or user account, malicious MCP servers/tools, audit log tampering by a
local attacker with write access, and denial of service outside the
gateway's budgets. Also out of scope: issues in third-party tools or
services AgentShield is used in front of, social engineering of a human
approver who rubber-stamps an approval without reading it, and
vulnerabilities that require the attacker to already be able to edit
policy files (assumption 1 in THREAT_MODEL.md — protect policy files
like code).

If you are unsure whether something is in scope, report it privately
anyway. A borderline report handled privately costs far less than a
real issue discussed in public.

## Status

This is a reference implementation. It has **not** been independently
reviewed and is **not** production-secure. Do not use it in front of
production systems or real secrets until reviewed.
