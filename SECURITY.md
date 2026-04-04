# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✓ Active  |
| 1.x     | ✗ EOL     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities in PIP itself.

Report vulnerabilities privately via:
**GitHub → Security → Advisories → Report a vulnerability**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)

We aim to acknowledge reports within 48 hours and resolve critical issues within 14 days.

## Scope

In-scope: vulnerabilities in PIP's own code that could allow an attacker to:
- Execute arbitrary commands on the machine running PIP
- Exfiltrate data outside the intended output directory
- Bypass the `--exploit` consent gate
- Expose secrets via the REST API without authentication

Out-of-scope: findings about the target system being tested (that's the point of the tool).

## Legal

PIP is designed exclusively for **authorised** security testing.
Use of PIP against systems without explicit written authorisation is illegal.
The maintainers accept no liability for misuse.
