# Security Policy

## Supported Versions

We release patches and security fixes for the current active release.

| Version | Burp Suite Edition | Caido Edition | Supported Status |
| :--- | :--- | :--- | :--- |
| 1.0.x | Supported | Supported | Active Maintenance |
| < 1.0.0 | Discontinued | Discontinued | Not Supported |

## Reporting a Vulnerability

Security is paramount in penetration testing tools. If you discover a vulnerability or security flaw in RequestVault (such as insecure temporary file creation, unsafe deserialization, path traversal, or credential leakage):

1. **Do not open a public issue.**
2. Report the vulnerability privately via GitHub Security Advisories:
   - Navigate to the **Security** tab of the repository.
   - Click **Report a vulnerability**.
   - Alternatively, reach out directly to the maintainer via GitHub ([@Kakaxh1](https://github.com/Kakaxh1)).

### What to Include in Your Report:
- Vulnerability description and impact on the testing environment.
- Target edition: Burp Suite or Caido.
- Proof of Concept (PoC) steps or sample HTTP transaction.
- Potential mitigations if identified.

We will acknowledge receipt within 48 hours and coordinate disclosure after verification.
