# Configuration Guide

This document explains how to configure ctl365 for managing Microsoft 365 tenants.

## Configuration Locations

All configuration files are stored in `~/.ctl365/`:

```
~/.ctl365/
├── config.toml              # Global settings (current tenant, log level)
├── tenants.toml             # Legacy tenant configurations
├── tenants.env              # Multi-tenant .env file (alternative format)
├── clients/                 # Individual client config files (recommended)
│   ├── reso.toml
│   ├── acme.toml
│   └── contoso.toml
├── cache/                   # Token cache (secure)
│   └── {tenant}.token
├── audit/                   # Audit history logs
│   ├── audit_{date}.json
│   └── session.json
├── reports/                 # Generated reports
│   └── {tenant}/
│       └── {report}_{timestamp}.html
└── exports/                 # Exported policies
    ├── {tenant}_policies_{timestamp}.json
    └── {tenant}_policies_{timestamp}.csv
```

## Client Configuration Files (Recommended)

The preferred way to configure clients is with individual TOML files in `~/.ctl365/clients/`.

### File Structure

Each client gets its own file: `~/.ctl365/clients/{abbreviation}.toml`

```toml
# ~/.ctl365/clients/reso.toml
# Client Configuration for RESO
# This file contains Azure credentials - keep it secure!

[client]
name = "Resolve Technology"
abbreviation = "RESO"
contact_email = "admin@resolvetech.com"
notes = "Primary MSP tenant"

[azure]
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
app_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# Optional: Set client_secret for unattended authentication
# If omitted, Device Code flow (interactive sign-in) will be used
# client_secret = "your-secret-here"

[branding]
logo_path = ""
primary_color = "#0078D4"
```

### Fields Reference

#### `[client]` Section

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Full name of the client/organization |
| `abbreviation` | Yes | Short code (e.g., RESO, ACME) - used as filename |
| `contact_email` | No | Primary contact email |
| `notes` | No | Internal notes about this client |
| `added_date` | No | Auto-set when importing |

#### `[azure]` Section

| Field | Required | Description |
|-------|----------|-------------|
| `tenant_id` | Yes | Azure AD Tenant ID (GUID) |
| `app_id` | Yes | Application (Client) ID from App Registration |
| `client_secret` | No | Client secret for unattended auth (if omitted, uses Device Code) |

#### `[branding]` Section

| Field | Default | Description |
|-------|---------|-------------|
| `logo_path` | `""` | Path to client logo (for reports) |
| `primary_color` | `#0078D4` | Primary brand color (hex) |

### Security Permissions

Client config files are created with restrictive permissions:
- **Unix**: `0600` (owner read/write only)
- **Windows**: User ACL only

**Important**: These files may contain client secrets. Keep them secure.

## Legacy Configuration

### tenants.toml

The legacy configuration format stores all tenants in a single file:

```toml
# ~/.ctl365/tenants.toml

[[tenants]]
name = "RESO"
tenant_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
auth_type = "devicecode"
description = "Resolve Technology"

[[tenants]]
name = "ACME"
tenant_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
client_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
client_secret = "secret-here"
auth_type = "clientcredentials"
description = "Acme Corporation"
```

### Multi-Tenant .env File

For quick setup, you can use a multi-tenant .env file:

```bash
# ~/.ctl365/tenants.env

[RESO]
NAME=Resolve Technology
TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=your-secret-here

[ACME]
NAME=Acme Corporation
TENANT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
CLIENT_ID=yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
CLIENT_SECRET=their-secret-here
```

### Per-Tenant .env Files

Single tenant .env files are also supported:

```bash
# ~/.ctl365/reso.env
TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=your-secret-here
DESCRIPTION=Resolve Technology
```

## Authentication Types

### Device Code Flow (Interactive)

Used when `client_secret` is not provided:

1. User runs a command
2. CLI displays a code and URL
3. User opens URL, enters code, and authenticates
4. Token is cached for future use

Best for: Manual administration, testing, one-time operations

### Client Credentials Flow (Unattended)

Used when `client_secret` is provided:

1. CLI authenticates directly with Azure AD
2. No user interaction required
3. Token is cached and auto-refreshed

Best for: Automation, scheduled tasks, CI/CD pipelines

## Managing Clients

### CLI Commands

```bash
# Add a new tenant via CLI
ctl365 tenant add RESO \
  --tenant-id "xxx-xxx" \
  --client-id "xxx-xxx" \
  --description "Resolve Technology"

# List all configured tenants
ctl365 tenant list

# Switch active tenant
ctl365 tenant switch RESO

# Remove a tenant
ctl365 tenant remove RESO
```

### TUI Client Management

In the TUI (`ctl365 tui`):

1. **Manage Clients** - View all configured clients
2. **Add New Client** - Interactive form to add a new client
3. **Delete Client** - Remove a client configuration
4. **Import from Config File** - Import clients from `~/.ctl365/clients/*.toml`

## Token Cache

Access tokens are cached in `~/.ctl365/cache/{tenant}.token`:

```json
{
  "access_token": "eyJ0...",
  "refresh_token": "0.AQY...",
  "expires_at": "2025-01-15T10:30:00Z",
  "tenant_id": "xxx-xxx"
}
```

### Token Behavior

- Tokens are automatically refreshed when expired
- Logout clears the token cache
- Each tenant has its own token file

### Clearing Tokens

```bash
# Logout from current tenant
ctl365 logout

# Logout from specific tenant
ctl365 logout --tenant RESO

# Logout from all tenants
ctl365 logout --all

# Or manually delete cache files
rm ~/.ctl365/cache/*.token
```

## Global Configuration

The `~/.ctl365/config.toml` file stores global settings:

```toml
current_tenant = "RESO"
log_level = "info"
default_tenant = "RESO"
```

## Environment Variables

You can override configuration with environment variables:

| Variable | Description |
|----------|-------------|
| `CTL365_TENANT` | Override active tenant |
| `CTL365_LOG_LEVEL` | Set log level (error, warn, info, debug, trace) |
| `TENANT_ID` | Tenant ID for single-tenant mode |
| `CLIENT_ID` | Client ID for single-tenant mode |
| `CLIENT_SECRET` | Client secret for single-tenant mode |

## Troubleshooting

### Config Not Found

```bash
# Check if config directory exists
ls -la ~/.ctl365/

# Create directory structure
mkdir -p ~/.ctl365/clients ~/.ctl365/cache

# Set proper permissions
chmod 700 ~/.ctl365
chmod 600 ~/.ctl365/tenants.toml
```

### Invalid Config File

```bash
# Validate TOML syntax
cat ~/.ctl365/clients/reso.toml

# Check for common issues:
# - Missing quotes around string values
# - Invalid GUID format for tenant_id/app_id
# - Trailing commas (not allowed in TOML)
```

### Permission Denied

On Unix systems, config files should have restricted permissions:

```bash
# Fix directory permissions
chmod 700 ~/.ctl365
chmod 700 ~/.ctl365/clients
chmod 700 ~/.ctl365/cache

# Fix file permissions
chmod 600 ~/.ctl365/tenants.toml
chmod 600 ~/.ctl365/clients/*.toml
chmod 600 ~/.ctl365/cache/*.token
```

## Best Practices

1. **Use individual client files** (`~/.ctl365/clients/`) for better organization
2. **Never commit secrets** to version control
3. **Use Device Code flow** for interactive work
4. **Use Client Credentials** for automation only
5. **Rotate client secrets** regularly
6. **Back up configurations** (excluding secrets) before upgrades
7. **Use meaningful abbreviations** (3-5 chars) for client names
