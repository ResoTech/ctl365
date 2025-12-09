# 🗺️ ctl365 Roadmap

## Current Status: MVP Complete ✅

All core features are implemented. Now focusing on production readiness and testing.

---

## 🔥 High Priority - Production Readiness

### 1. Testing with App Registration
**Status**: Ready to test
**Blockers**: Need app registration setup complete

- [ ] Test authentication flows (device code + client credentials)
- [ ] Test Windows baseline deployment
- [ ] Test macOS baseline deployment
- [ ] Test iOS baseline deployment
- [ ] Test Android baseline deployment
- [ ] Test Conditional Access policy deployment
- [ ] Test Autopilot device import and profile creation
- [ ] Test application deployment (Win32, M365)
- [ ] Test export/import with real tenant data
- [ ] Test drift detection and auto-remediation

**Required Permissions** (verify in app registration):
```
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
Directory.ReadWrite.All
Policy.ReadWrite.ConditionalAccess
Group.ReadWrite.All
```

### 2. Error Handling & Resilience
**Priority**: High
**Effort**: Medium

- [ ] Add retry logic with exponential backoff
- [ ] Handle Graph API rate limiting (429 responses)
- [ ] Better error messages for common failures
  - Invalid credentials
  - Missing permissions
  - Policy conflicts
  - Quota exceeded
- [ ] Partial failure handling (continue on error)
- [ ] Timeout configuration for long operations

### 3. Safety Features
**Priority**: High
**Effort**: Low

- [ ] `--dry-run` flag for all destructive operations
  - `baseline apply --dry-run`
  - `ca deploy --dry-run`
  - `autopilot import --dry-run`
  - `audit drift --fix --dry-run`
- [ ] Confirmation prompts for:
  - Deleting policies
  - Deleting Autopilot devices
  - Modifying Conditional Access
  - Bulk operations
- [ ] `--yes` / `-y` flag to skip confirmations (for automation)

### 4. Documentation
**Priority**: High
**Effort**: Medium

- [ ] Update README.md with:
  - Complete feature list
  - Installation instructions
  - Quick start guide
  - Screenshots/GIFs
- [ ] Create `docs/PERMISSIONS.md` - Required app registration permissions
- [ ] Create `docs/TROUBLESHOOTING.md` - Common issues and solutions
- [ ] Create `examples/` folder with:
  - Sample baseline JSONs for all platforms
  - Sample Autopilot CSV
  - Sample group mapping JSON
  - Sample CA deployment scripts
- [ ] Add inline code documentation (rustdoc)

---

## 🚀 Medium Priority - Enhanced Features

### 5. Logging & Observability
**Priority**: Medium
**Effort**: Low

- [ ] Structured logging with `tracing`
- [ ] Log levels: ERROR, WARN, INFO, DEBUG, TRACE
- [ ] `-v`, `-vv`, `-vvv` verbosity flags
- [ ] Log to file option: `--log-file audit.log`
- [ ] JSON log format option for automation

### 6. Progress Indicators
**Priority**: Medium
**Effort**: Low

- [ ] Progress bars for long operations
  - Baseline apply with multiple policies
  - Autopilot bulk import
  - Export all policies
- [ ] Spinner for API calls
- [ ] Time estimates for operations

### 7. Validation & Pre-flight Checks
**Priority**: Medium
**Effort**: Medium

- [ ] Validate baseline JSON before applying
- [ ] Check required permissions before operations
- [ ] Warn about conflicting policies
- [ ] Validate Autopilot CSV format before import
- [ ] Check group existence before assignment

### 8. Policy Templates Library
**Priority**: Medium
**Effort**: High

- [ ] CIS Benchmark baselines
- [ ] NIST 800-171 compliance templates
- [ ] PCI-DSS templates
- [ ] HIPAA compliance templates
- [ ] Microsoft Security Baseline (official)
- [ ] Template versioning and updates

---

## 🎨 Low Priority - Quality of Life

### 9. Interactive Mode
**Priority**: Low
**Effort**: Medium

- [ ] Interactive baseline builder
  - Wizard-style questions
  - Platform selection
  - Feature toggles (encryption, MFA, etc.)
- [ ] Interactive group selection
- [ ] Interactive tenant switching

### 10. Backup & Rollback
**Priority**: Low
**Effort**: High

- [ ] `ctl365 backup` - Snapshot current tenant config
- [ ] `ctl365 restore` - Rollback to previous state
- [ ] Automatic backup before apply
- [ ] Backup versioning and history

### 11. Reporting Enhancements
**Priority**: Low
**Effort**: Medium

- [ ] PDF report generation
- [ ] Email report delivery
- [ ] Scheduled compliance checks
- [ ] Trend analysis over time
- [ ] Dashboard integration (webhook to external tools)

### 12. Advanced Autopilot Features
**Priority**: Low
**Effort**: Medium

- [ ] Bulk profile updates
- [ ] Device re-assignment
- [ ] Autopilot reset operations
- [ ] ESP (Enrollment Status Page) configuration
- [ ] Hardware hash extraction from running device

---

## 🔧 Infrastructure & Release

### 13. Testing Infrastructure
**Priority**: High
**Effort**: High

- [ ] Unit tests for all template generators
- [ ] Integration tests with mocked Graph API
- [ ] E2E tests with test tenant
- [ ] Test coverage reporting
- [ ] Automated testing in CI

### 14. CI/CD Pipeline
**Priority**: High
**Effort**: Medium

- [ ] GitHub Actions workflow
- [ ] Automated builds on push
- [ ] Automated tests on PR
- [ ] Cross-platform builds (Linux, macOS, Windows)
- [ ] Release automation
- [ ] Binary artifact publishing

### 15. Distribution
**Priority**: Medium
**Effort**: Medium

- [ ] GitHub Releases with binaries
- [ ] Installation script: `curl -sSL install.ctl365.dev | sh`
- [ ] Homebrew formula (macOS/Linux)
- [ ] Chocolatey package (Windows)
- [ ] Scoop manifest (Windows)
- [ ] Docker image (optional)
- [ ] Publish to crates.io

### 16. Security Audit
**Priority**: High
**Effort**: High

- [ ] Code security review
- [ ] Dependency audit (`cargo audit`)
- [ ] Token storage security review
- [ ] Input validation review
- [ ] Supply chain security (SBOMs)

---

## 🌟 Future Enhancements

### 17. GitOps Integration
**Priority**: Future
**Effort**: High

- [ ] Watch Git repo for baseline changes
- [ ] Auto-apply on commit
- [ ] Drift correction via pull requests
- [ ] Multi-branch support (dev/staging/prod)

### 18. Web Dashboard
**Priority**: Future
**Effort**: Very High

- [ ] Tauri-based desktop app
- [ ] React/Svelte UI with shadcn/ui
- [ ] Visual baseline builder
- [ ] Real-time compliance monitoring
- [ ] Multi-tenant overview

### 19. Advanced Integrations
**Priority**: Future
**Effort**: High

- [ ] Slack/Teams notifications
- [ ] Webhook support for events
- [ ] Integration with ticketing systems
- [ ] API server mode (REST API)
- [ ] Terraform provider

---

## 📊 Testing Checklist (Next Immediate Steps)

Since you have an app registration ready, here's the testing priority order:

### Phase 1: Authentication & Basic Operations
- [ ] Test `ctl365 login` with device code flow
- [ ] Test `ctl365 tenant add` and multi-tenant switching
- [ ] Test `ctl365 baseline list`
- [ ] Verify token caching works correctly

### Phase 2: Windows Baseline (Most Mature)
- [ ] Generate Windows OIB baseline
- [ ] Apply to test tenant with `--dry-run`
- [ ] Apply to test tenant for real
- [ ] Verify policies appear in Intune portal
- [ ] Test group assignment

### Phase 3: Other Platforms
- [ ] Test macOS baseline deployment
- [ ] Test iOS baseline deployment
- [ ] Test Android baseline deployment

### Phase 4: Advanced Features
- [ ] Test Conditional Access deployment
- [ ] Test Autopilot import
- [ ] Test application deployment
- [ ] Test export/import workflow
- [ ] Test drift detection

### Phase 5: Error Cases
- [ ] Test with invalid credentials
- [ ] Test with missing permissions
- [ ] Test network failures
- [ ] Test malformed input files

---

## 🎯 Definition of Done for v1.0 Release

- [x] All core features implemented
- [ ] Tested with real tenant (all platforms)
- [ ] Documentation complete (README, examples, troubleshooting)
- [ ] `--dry-run` flag implemented
- [ ] Basic error handling and retry logic
- [ ] CI/CD pipeline setup
- [ ] Cross-platform binaries built
- [ ] GitHub release published
- [ ] Installation methods available (curl script, package managers)

---

**Next Steps**: Start testing with your app registration and document any issues/bugs found!
