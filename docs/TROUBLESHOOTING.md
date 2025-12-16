# Troubleshooting Guide

Common issues and solutions for ctl365.

---

## Authentication Issues

### "Access token is empty" / 401 Unauthorized

**Symptoms:**
```
Error: InvalidAuthenticationToken - Access token is empty.
```

**Causes:**
- Token has expired
- Never logged in
- Wrong tenant selected

**Solutions:**
```bash
# Re-authenticate
ctl365 login ACME

# Check current tenant
ctl365 tenant list --detailed

# Switch to correct tenant
ctl365 tenant switch ACME
```

---

### "Insufficient privileges" / 403 Forbidden

**Symptoms:**
```
Error: Authorization_RequestDenied - Insufficient privileges to complete the operation.
```

**Causes:**
- Missing Graph API permissions
- Admin consent not granted
- Using delegated flow without user consent

**Solutions:**

1. **Verify app registration permissions** in Azure Portal:
   - Go to Azure AD > App registrations > Your app > API permissions
   - Required permissions:
     ```
     DeviceManagementConfiguration.ReadWrite.All
     DeviceManagementApps.ReadWrite.All
     DeviceManagementManagedDevices.ReadWrite.All
     DeviceManagementServiceConfig.ReadWrite.All
     Directory.ReadWrite.All
     Group.ReadWrite.All
     Policy.ReadWrite.ConditionalAccess
     ```

2. **Grant admin consent:**
   - In API permissions, click "Grant admin consent for [tenant]"
   - Wait 5 minutes for propagation

3. **Re-authenticate:**
   ```bash
   ctl365 logout --tenant ACME
   ctl365 login ACME
   ```

See: [APP_REGISTRATION.md](APP_REGISTRATION.md)

---

### Device Code Flow Timeout

**Symptoms:**
```
Error: Device code expired. Please try again.
```

**Cause:** Did not complete authentication within 15 minutes

**Solution:**
```bash
# Try again and complete auth faster
ctl365 login ACME
```

---

### Client Credentials Flow Fails

**Symptoms:**
```
Error: AADSTS7000215: Invalid client secret provided.
```

**Causes:**
- Client secret expired
- Wrong client secret
- Using delegated permissions with client credentials

**Solutions:**

1. **Check secret expiry** in Azure Portal:
   - Azure AD > App registrations > Your app > Certificates & secrets
   - Create new secret if expired

2. **Update tenant configuration:**
   ```bash
   ctl365 tenant remove ACME
   ctl365 tenant add ACME \
     --tenant-id "..." \
     --client-id "..." \
     --client-secret "NEW-SECRET" \
     --client-credentials
   ```

3. **Use Application permissions** (not Delegated) for client credentials flow

---

## Configuration Issues

### "Config directory not found"

**Symptoms:**
```
Error: Failed to read config file
```

**Solution:**
```bash
# Linux/macOS
mkdir -p ~/.config/ctl365/cache

# Windows (PowerShell)
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\ctl365\cache"
```

---

### "No tenant configured"

**Symptoms:**
```
Error: No active tenant. Run 'ctl365 tenant add' first.
```

**Solution:**
```bash
# Add a tenant (use a 4-char client identifier)
ctl365 tenant add ACME \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID"

# Login
ctl365 login ACME
```

---

### Wrong Tenant Active

**Symptoms:**
- Commands affecting wrong tenant
- "Resource not found" for known resources

**Solution:**
```bash
# Check active tenant
ctl365 tenant list

# Switch tenant
ctl365 tenant switch ACME
```

---

## API Errors

### 429 Rate Limited

**Symptoms:**
```
Error: TooManyRequests - Request rate limit exceeded.
```

**Cause:** Too many API requests in short period

**Solution:**
- ctl365 automatically handles rate limits with retry
- Wait and retry manually if persistent
- Use `--dry-run` to preview without API calls

---

### 500 Internal Server Error

**Symptoms:**
```
Error: InternalServerError - An error occurred.
```

**Cause:** Transient Microsoft service issue

**Solutions:**
- ctl365 automatically retries 5xx errors
- Wait a few minutes and retry
- Check [Microsoft 365 Service Health](https://admin.microsoft.com/Adminportal/Home#/servicehealth)

---

### 404 Not Found

**Symptoms:**
```
Error: Request_ResourceNotFound - Resource not found.
```

**Causes:**
- Resource doesn't exist
- Wrong ID provided
- Resource in different tenant

**Solutions:**
```bash
# Verify you're in correct tenant
ctl365 tenant list --detailed

# List resources to find correct ID
ctl365 baseline list
ctl365 ca list
ctl365 autopilot list
```

---

## Baseline Issues

### "Policy already exists"

**Symptoms:**
```
Error: Policy with displayName 'X' already exists.
```

**Cause:** Trying to create duplicate policy

**Solutions:**
```bash
# Use --dry-run to preview first
ctl365 baseline apply --file baseline.json --dry-run

# Delete existing and recreate
# Or use export/import with conflict resolution
```

---

### Invalid Baseline JSON

**Symptoms:**
```
Error: Failed to parse baseline file
```

**Causes:**
- Malformed JSON
- Missing required fields
- Wrong schema version

**Solutions:**
```bash
# Validate JSON syntax
cat baseline.json | python3 -m json.tool

# Generate fresh baseline
ctl365 baseline new windows --template oib -o baseline.json
```

---

## Autopilot Issues

### CSV Import Fails

**Symptoms:**
```
Error: Invalid CSV format
```

**Cause:** Wrong CSV column headers or format

**Required CSV format:**
```csv
Device Serial Number,Windows Product ID,Hardware Hash
ABC123,XXXXX-XXXXX-XXXXX-XXXXX-XXXXX,Base64EncodedHash...
```

**Solution:**
- Ensure headers match exactly
- Export from Windows Settings > Accounts > Access work or school
- Use hardware hash collection script from Microsoft

---

### Device Not Appearing

**Symptoms:**
- Device imported but not visible in Intune
- "Device not found" errors

**Solutions:**
```bash
# Force sync
ctl365 autopilot sync

# Wait 5-10 minutes for propagation

# Check device status
ctl365 autopilot list --detailed
```

---

## Build/Development Issues

### Tests Fail with "let chains" Error

**Symptoms:**
```
error[E0658]: `let` expressions in this position are unstable
```

**Cause:** Running tests with stable Rust instead of nightly

**Solution:**
```bash
# Install nightly if needed
rustup install nightly

# Run tests with nightly
cargo +nightly test
```

See: [docs/rust/DEPENDENCIES.md](rust/DEPENDENCIES.md)

---

### Compilation Errors After Update

**Symptoms:**
```
error[E0412]: cannot find type...
```

**Solutions:**
```bash
# Clean build
cargo clean
cargo build --release

# Update dependencies
cargo update
cargo build --release
```

---

## TUI Issues

### TUI Not Rendering Correctly

**Symptoms:**
- Garbled display
- Missing borders
- Wrong colors

**Causes:**
- Terminal doesn't support required features
- SSH session without proper terminfo

**Solutions:**
```bash
# Set terminal type
export TERM=xterm-256color

# Use supported terminal emulators:
# - Windows Terminal
# - iTerm2
# - Alacritty
# - Kitty
```

---

### TUI Keyboard Not Working

**Symptoms:**
- Keys not recognized
- Navigation broken

**Causes:**
- Terminal key mapping issues
- tmux/screen interference

**Solutions:**
```bash
# Try without tmux/screen first
# Check terminal settings for key passthrough

# Use CLI commands instead of TUI
ctl365 baseline list
ctl365 ca deploy --all --dry-run
```

---

## Performance Issues

### Commands Taking Too Long

**Possible causes:**
- Slow network connection
- Large number of resources
- Graph API latency

**Solutions:**
```bash
# Use --verbose for progress info
ctl365 --verbose baseline apply --file baseline.json

# Use batch operations where possible
# Consider time of day (avoid peak hours)
```

---

## Getting Help

### Enable Debug Logging

```bash
# Verbose output
ctl365 --verbose <command>

# Set log level
export CTL365_LOG_LEVEL=debug
ctl365 <command>
```

### Check Version

```bash
ctl365 --version
```

### Report Issues

- Check existing issues: [GitHub Issues](https://github.com/yourusername/ctl365/issues)
- Include:
  - ctl365 version
  - Command that failed
  - Full error message
  - Relevant config (redact secrets!)

---

## See Also

- [APP_REGISTRATION.md](APP_REGISTRATION.md) - Azure AD setup
- [QUICKSTART.md](QUICKSTART.md) - Getting started
- [rust/DEPENDENCIES.md](rust/DEPENDENCIES.md) - Build requirements
- [rust/TESTING.md](rust/TESTING.md) - Running tests
