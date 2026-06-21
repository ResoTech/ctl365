# Security Policy

## Supported Versions

CTL365 is currently developed as a single active release line.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes |
| < 0.1   | No |

## Reporting a Vulnerability

Please do not open public GitHub issues for suspected security vulnerabilities.

Report security issues privately to `security@resolvetechnology.com`.

Include the following when possible:

- A description of the issue and affected command or feature
- Reproduction steps or a proof of concept
- The impact you expect
- Your environment: OS, ctl365 version, and whether you used device code or client credentials auth

You can expect:

- An acknowledgment within 5 business days
- A follow-up request if reproduction details are incomplete
- Status updates as the issue is triaged and fixed

If you do not receive a response within 5 business days, open a minimal GitHub issue asking for an alternate security contact without disclosing the vulnerability details.

## Disclosure Guidelines

- Do not publicly disclose the issue until a fix or mitigation is available.
- Avoid accessing data that does not belong to you.
- Avoid destructive testing, denial-of-service, or persistence on systems you do not own.

## Credential Handling Notes

CTL365 interacts with Microsoft 365 and may store sensitive material locally, including:

- OAuth access tokens
- OAuth refresh tokens
- Tenant configuration
- Optional client secrets for unattended authentication

Current implementation notes:

- On Unix-like systems, CTL365 attempts to store sensitive files with owner-only permissions.
- Secrets are currently stored in plaintext on disk and are not yet protected by OS keyring integration.
- Users should prefer device code authentication when unattended access is not required.
- For automation, prefer secret injection through a secure vault or environment management system rather than shell history.

## Hardening Recommendations

- Use full-disk encryption on administrator workstations.
- Rotate Microsoft Entra app secrets regularly.
- Grant least-privilege Graph permissions.
- Protect CI/CD secrets with a dedicated secret manager.
- Review local token and config storage on shared systems.
