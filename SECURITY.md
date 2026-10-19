# Security Policy

## Supported Versions

We release patches and bug fixes for the current active release.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

Security is paramount in penetration testing tools. If you discover a vulnerability or security flaw in RequestVault (such as an insecure temporary file creation, unsafe deserialization, or credential leakage):

1. **Do not open a public issue.**
2. Report the vulnerability privately via GitHub Security Advisories:
   - Navigate to the **Security** tab of the repository.
   - Click **Report a vulnerability**.
   - Alternatively, reach out directly to the maintainer via GitHub ([@Kakaxh1](https://github.com/Kakaxh1)).

### What to Include in Your Report:
- Type of vulnerability (e.g. path traversal, memory leak, credential exposure).
- Full steps to reproduce or Proof-of-Concept traffic.
- Impact on Burp Suite or the local assessment environment.
- Potential mitigations if known.

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.
