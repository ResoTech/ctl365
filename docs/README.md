# 📚 ctl365 Documentation

Welcome to the **ctl365** documentation!

---

## 🚀 Getting Started

**New to ctl365?** Start here:

1. **[App Registration Setup](APP_REGISTRATION.md)** ⭐ **Start Here!**
   - Create Azure AD app registration
   - Configure Microsoft Graph permissions
   - Get your credentials (Tenant ID, Client ID)

2. **[Quick Start Guide](../QUICKSTART.md)**
   - Install ctl365
   - Add your first tenant
   - Run your first baseline

3. **[Authentication Testing](../TEST_AUTHENTICATION.md)**
   - Test device code flow
   - Test client credentials flow
   - Troubleshooting auth issues

---

## 📖 Core Concepts

### Authentication Methods

**ctl365** supports two authentication methods:

| Method | Use Case | Requires Browser | Best For |
|--------|----------|------------------|----------|
| **Device Code Flow** | Interactive admin tasks | ✅ Yes | Day-to-day operations, testing |
| **Client Credentials** | Automation/CI-CD | ❌ No | Scheduled jobs, pipelines |

See: [APP_REGISTRATION.md](APP_REGISTRATION.md)

---

### Multi-Tenant Management

Manage multiple M365 tenants from a single ctl365 installation:

```bash
# Add multiple tenants
ctl365 tenant add customer-a --tenant-id ... --client-id ...
ctl365 tenant add customer-b --tenant-id ... --client-id ...

# Switch between them
ctl365 tenant switch customer-a
ctl365 tenant switch customer-b

# List all tenants
ctl365 tenant list --verbose
```

---

### Baseline Management (Coming in Phase 2)

Deploy security baselines to your tenants:

```bash
# Generate baseline
ctl365 baseline new windows --template openintune

# Apply baseline
ctl365 baseline apply --file baseline.json --tenant prod

# Export existing config
ctl365 baseline export --tenant prod --path ./backup/
```

---

## 📋 Command Reference

### Authentication Commands

```bash
# Login to tenant (device code flow)
ctl365 login --tenant my-tenant

# Login with quick setup (auto-creates tenant config)
ctl365 login --tenant-id "..." --client-id "..."

# Logout from current tenant
ctl365 logout

# Logout from all tenants
ctl365 logout --all
```

---

### Tenant Management

```bash
# Add new tenant
ctl365 tenant add <name> --tenant-id "..." --client-id "..."

# Add with client secret (automation)
ctl365 tenant add <name> \
  --tenant-id "..." \
  --client-id "..." \
  --client-secret "..." \
  --client-credentials

# List all tenants
ctl365 tenant list
ctl365 tenant list --verbose  # Show auth status

# Switch active tenant
ctl365 tenant switch <name>

# Remove tenant
ctl365 tenant remove <name>
```

---

### Baseline Management (Phase 2)

```bash
# Generate new baseline
ctl365 baseline new windows --template openintune
ctl365 baseline new macos --template openintune
ctl365 baseline new windows --template microsoft-security-baseline

# Apply baseline to tenant
ctl365 baseline apply --file baseline.json --tenant prod
ctl365 baseline apply --file baseline.json --dry-run

# Export existing config
ctl365 baseline export --tenant prod --path ./backup/

# List baselines
ctl365 baseline list
```

---

### Conditional Access (Phase 4)

```bash
# Deploy CA baseline
ctl365 ca deploy --baseline modern-2025 --mode report-only

# Analyze report-only policy
ctl365 ca analyze --policy CAD001 --days 7

# Enable policy (promote report-only → enforced)
ctl365 ca enable --policy CAD001

# Block countries
ctl365 ca block-countries --except US,CA
```

---

### Compliance & Auditing (Phase 5)

```bash
# Run compliance audit
ctl365 audit --standard cis --tenant prod
ctl365 audit --standard scuba --products aad,defender,exo
ctl365 audit --standard openintune

# Generate compliance report
ctl365 report --format html --output report.html
ctl365 report --format json --output report.json
ctl365 report --format csv --output report.csv

# Detect drift
ctl365 drift --baseline ./prod-baseline/ --tenant prod
```

---

## 🔧 Configuration

### Config File Locations

```
~/.config/ctl365/              # Linux/macOS
%LOCALAPPDATA%\ctl365\         # Windows

├── config.toml                # Global settings
├── tenants.toml               # Tenant configurations
└── cache/
    ├── tenant-a.token         # Cached access tokens
    └── tenant-b.token
```

---

### Config File Format

**config.toml** (global settings):
```toml
default_tenant = "my-tenant"
current_tenant = "my-tenant"
log_level = "info"
```

**tenants.toml** (tenant registry):
```toml
[[tenants]]
name = "my-tenant"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "11111111-1111-1111-1111-111111111111"
auth_type = "devicecode"
description = "Production tenant"

[[tenants]]
name = "automation-tenant"
tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
client_id = "ffffffff-0000-1111-2222-333333333333"
client_secret = "your-secret-here"
auth_type = "clientcredentials"
```

---

## 🐛 Troubleshooting

### Common Issues

**Authentication fails:**
- Check [APP_REGISTRATION.md](APP_REGISTRATION.md) for permission setup
- Verify admin consent granted
- Check tenant ID and client ID are correct

**Token expired:**
```bash
# Just login again
ctl365 login --tenant my-tenant
```

**Can't find config directory:**
```bash
# Create it manually
mkdir -p ~/.config/ctl365/cache
```

**Permission denied errors:**
- Verify Graph API permissions granted in Azure AD
- Check admin consent status
- Wait 5 minutes for permission changes to propagate

---

## 📚 Reference Materials

### Baselines & Standards

**ctl365** is built on industry-leading security frameworks:

- **CISA ScubaGear** - Government compliance baselines
- **CIS Microsoft 365 Benchmark** - Industry standard
- **OpenIntuneBaseline** - Microsoft MVP-curated
- **Microsoft Security Baselines** - Official recommendations

See: [REFERENCE_ANALYSIS.md](../REFERENCE_ANALYSIS.md)

---

### Microsoft Graph API

**ctl365** uses Microsoft Graph API to manage M365:

- [Microsoft Graph Documentation](https://learn.microsoft.com/en-us/graph/)
- [Intune Graph API](https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview)
- [Conditional Access API](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)

---

## 🛠️ Development

### Building from Source

```bash
git clone https://github.com/yourusername/ctl365
cd ctl365
cargo build --release

# Binary location:
# target/x86_64-unknown-linux-gnu/release/ctl365
```

---

### Project Structure

```
ctl365/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── cmd/                 # Command implementations
│   │   ├── login.rs
│   │   ├── tenant.rs
│   │   └── baseline.rs
│   ├── graph/               # Microsoft Graph API
│   │   ├── auth.rs          # OAuth2 authentication
│   │   ├── intune.rs        # Intune APIs
│   │   └── conditional_access.rs
│   ├── config/              # Configuration management
│   └── templates/           # Baseline templates
├── docs/                    # Documentation (you are here!)
├── archive/                 # Reference materials
└── Cargo.toml               # Rust dependencies
```

---

## 🤝 Contributing

Contributions welcome! See:
- **[STATUS.md](../STATUS.md)** - Current project status
- **[TODO.md](../TODO.md)** - Roadmap
- **GitHub Issues** - Report bugs or request features

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 🎯 Next Steps

1. **[Set up your app registration](APP_REGISTRATION.md)**
2. **[Test authentication](../TEST_AUTHENTICATION.md)**
3. **[Run your first baseline](../QUICKSTART.md)** (Phase 2)

---

**Questions?** Open an issue on GitHub or check the troubleshooting section above.

**ctl365** — *Control your cloud. Define your baseline.* 🚀
