# CTL365 Security Model

This document describes the security architecture, authentication flows, credential storage, and threat considerations for CTL365.

## Overview

CTL365 is a command-line tool that manages Microsoft 365 tenants via the Microsoft Graph API. It handles sensitive credentials including OAuth tokens, tenant IDs, and optionally client secrets.

## Authentication Flows

CTL365 supports two OAuth2 authentication flows:

### Device Code Flow (Interactive)

Used when `client_secret` is not configured. This is the recommended flow for manual administration.

**How it works:**
1. User runs `ctl365 login TENANT`
2. CLI requests a device code from Azure AD
3. User visits `microsoft.com/devicelogin` and enters the code
4. User authenticates in browser (supports MFA)
5. CLI polls Azure AD for token completion
6. Access token is cached locally

**Security properties:**
- No secrets stored on disk (most secure)
- Supports MFA enforcement via Conditional Access
- Refresh tokens enable session persistence
- User identity audited in Azure AD sign-in logs
- Delegated permissions (actions taken as the user)

**Best for:**
- Manual administration
- Testing and development
- One-time operations
- Environments requiring MFA

### Client Credentials Flow (Unattended)

Used when `client_secret` is configured. Required for automation and scheduled tasks.

**How it works:**
1. CLI reads client_secret from config file
2. Direct token request to Azure AD with app credentials
3. Access token returned immediately
4. Token cached locally

**Security properties:**
- Client secret must be protected on disk
- Requires application permissions (not delegated)
- No user context - actions logged as the application identity
- No MFA (the secret IS the credential)
- Suitable for CI/CD and automation

**Best for:**
- Scheduled automation
- CI/CD pipelines
- Scripts running unattended
- Bulk operations

## Credential Storage

### File Locations

| File | Purpose | Permissions |
|------|---------|-------------|
| `~/.ctl365/clients/*.toml` | Tenant configs (may include client_secret) | 0600 |
| `~/.ctl365/tenants.toml` | Legacy tenant registry | 0600 |
| `~/.ctl365/cache/*.token` | OAuth access/refresh tokens | 0600 |

On Windows, files are stored in `%LOCALAPPDATA%\ctl365\` with user-only ACLs.

### Token Cache Structure

```json
{
  "access_token": "eyJ0...",
  "refresh_token": "0.AQY...",
  "expires_at": "2025-01-15T10:30:00Z",
  "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### Security Considerations

**Current implementation:**
- Tokens and secrets stored as plaintext JSON/TOML
- Protected by filesystem permissions (0600 on Unix)
- Directory permissions set to 0700
- Access tokens expire in ~1 hour
- Refresh tokens valid up to 90 days (Azure AD default)

**Limitations:**
1. **No encryption at rest** - Files are plaintext on disk
2. **No OS keyring integration** - Not using macOS Keychain, Windows Credential Manager, or Linux Secret Service
3. **Single-user design** - Permissions protect from other users but not from processes running as the same user

## Threat Model

### In-Scope Threats (Mitigated)

| Threat | Mitigation |
|--------|------------|
| Other users reading credentials | 0600 file permissions |
| Accidental git commits | Files stored in ~/.ctl365 (outside repos) |
| Token expiration attacks | Automatic refresh, clear expiration errors |
| API rate limiting DoS | Exponential backoff with jitter |
| Man-in-the-middle | HTTPS with rustls (modern TLS) |

### Out-of-Scope Threats (Not Mitigated)

| Threat | Notes |
|--------|-------|
| Malware on user's machine | No practical defense at CLI level |
| Root/admin access | Can bypass file permissions |
| Memory scraping | Tokens held in memory during execution |
| Stolen device (unencrypted disk) | Use full-disk encryption (OS level) |
| Compromised Azure AD app | Revoke app, rotate secrets |

## Recommended Security Practices

### For All Environments

1. **Use Device Code flow when possible** - No secrets stored on disk
2. **Enable Conditional Access** - Require compliant devices, trusted networks
3. **Monitor Azure AD logs** - Review sign-in and audit logs regularly
4. **Use full-disk encryption** - Protects credentials if device is stolen

### For Automation (Client Credentials)

1. **Rotate secrets annually** - Or more frequently per your policy
2. **Use separate apps per environment** - Dev, staging, production
3. **Apply least privilege** - Only grant required Graph permissions
4. **Consider certificate auth** - More secure than client secrets (future)

### For CI/CD

1. **Use environment variables** - Don't commit secrets to repos
2. **Store secrets in vault** - Azure Key Vault, HashiCorp Vault, etc.
3. **Limit secret exposure** - Use short-lived credentials when possible
4. **Audit pipeline access** - Monitor who can access CI/CD secrets

## API Permissions

### Delegated Permissions (Device Code)

Required for interactive operations:
- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `Group.ReadWrite.All`

### Application Permissions (Client Credentials)

Same as delegated, plus:
- Requires admin consent
- Actions logged as application, not user
- Broader scope (all resources, not just user's)

See [APP_REGISTRATION.md](APP_REGISTRATION.md) for detailed setup instructions.

## Compliance Considerations

### Audit Trail

All Graph API calls are logged by Microsoft:
- **Azure AD Sign-in logs** - Authentication events
- **Unified Audit Log** - Graph API operations
- **Intune Audit logs** - Device management changes

CTL365 actions are traceable via:
- Application ID (for client credentials)
- User principal name (for device code)
- Client IP address
- Timestamp and operation details

### Data Handling

**CTL365 does NOT:**
- Store Microsoft 365 user data locally (beyond tokens)
- Transmit data to third parties
- Collect telemetry or usage analytics
- Cache policy content after operations

**CTL365 DOES:**
- Cache OAuth tokens locally (required for operation)
- Store tenant configuration locally
- Generate reports saved to local filesystem
- Log operations to local files (when enabled)

## Future Security Improvements

### Planned Enhancements

1. **OS Keyring Integration**
   - macOS: Keychain Services
   - Windows: Windows Credential Manager
   - Linux: Secret Service API (GNOME Keyring, KWallet)
   - Would eliminate plaintext secret storage

2. **Certificate-Based Authentication**
   - Replace client secrets with certificates
   - Private keys stored in OS keystore
   - Better audit trail and rotation management

3. **Encryption at Rest**
   - Encrypt token cache with user-derived key
   - Optional for high-security environments

## References

- [Microsoft Graph Authentication](https://learn.microsoft.com/en-us/graph/auth/)
- [Device Code Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)
- [Client Credentials Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph Permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)
