# ctl365 Documentation

Documentation for **ctl365** — control, configure, and secure Microsoft 365 at scale.

## Getting Started
- [Getting Started](getting-started/getting-started.md) - Zero to first baseline
- [Quickstart](getting-started/quickstart.md) - Features overview & quick deploy
- [App Registration](getting-started/app-registration.md) - Azure AD app setup (start here)
- [Configuration](getting-started/configuration.md) - Config files & locations

## Reference
- [Commands](reference/commands.md) - Full CLI command reference
- [Permissions](reference/permissions.md) - Microsoft Graph API permissions
- [Exchange](reference/exchange.md) - Exchange Online configuration reference

## Guides
- [Windows Autopilot](guides/windows-autopilot.md) - Autopilot baseline deployment
- [macOS Deployment](guides/macos-deployment.md) - macOS zero-touch deployment
- [Apple MDM Push Certificate](guides/apple-mdm-push-certificate.md) - Apple MDM setup
- [Tenant Baseline](guides/tenant-baseline.md) - Tenant-wide baseline configuration
- [Troubleshooting](guides/troubleshooting.md) - Common issues & solutions

## Testing
- [Testing Guide](testing/testing-guide.md) - Feature testing methodology
- [Authentication Testing](testing/authentication-testing.md) - Auth testing
- [Rust Testing](testing/rust-testing.md) - Rust test infrastructure

## Internals
- [Security Model](internals/security-model.md) - Security architecture
- [Dependencies](internals/dependencies.md) - Rust dependencies & toolchain

## Security Advisories
- [Accepted](advisories/accepted.md) - Advisories we currently accept
- [Resolved](advisories/resolved.md) - Previously-flagged, now resolved

---

## Quick Reference

### Authentication Methods

| Method | Use Case | Requires Browser | Best For |
|--------|----------|------------------|----------|
| **Device Code Flow** | Interactive admin tasks | Yes | Day-to-day operations, testing |
| **Client Credentials** | Automation/CI-CD | No | Scheduled jobs, pipelines |

### Config File Locations

```
~/.config/ctl365/              # Linux/macOS
%LOCALAPPDATA%\ctl365\         # Windows

├── config.toml                # Global settings
├── tenants.toml               # Tenant registry
└── cache/
    └── <tenant>.token         # Cached access tokens
```

---

**ctl365** - *Control your cloud. Define your baseline.*
