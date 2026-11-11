# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Email the
maintainer privately with:

- a description of the issue and its impact,
- steps to reproduce (policy file + call sequence if applicable),
- any suggested fix.

You will receive an acknowledgement, and the issue will be fixed and
disclosed after a fix is available.

## Scope

In scope: the policy engine, gateway check order, approval binding, secret
broker/redaction, budget enforcement, and audit log integrity in this
repository.

Out of scope (known limitations, see THREAT_MODEL.md): compromise of the
host or user account, malicious MCP servers/tools, audit log tampering by a
local attacker with write access, and denial of service outside the
gateway's budgets.

## Status

This is a reference implementation. It has **not** been independently
reviewed and is **not** production-secure. Do not use it in front of
production systems or real secrets until reviewed.
