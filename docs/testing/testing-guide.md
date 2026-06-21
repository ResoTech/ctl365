# 🧪 Testing Guide - ctl365

## Prerequisites

✅ You have an app registration setup (see `docs/APP_REGISTRATION.md`)
✅ You have the following from Azure AD:
- Application (client) ID
- Directory (tenant) ID
- Admin consent granted for permissions

---

## 🎯 Testing Phases

### Phase 1: Authentication & Configuration (15 min)

#### 1.1 Add Your Tenant
```bash
# Replace with your actual IDs
ctl365 tenant add test-tenant \
  --tenant-id "YOUR-TENANT-ID" \
  --client-id "YOUR-CLIENT-ID" \
  --description "Testing tenant for ctl365"
```

**Expected Output:**
```
✓ Tenant added: test-tenant
→ Tenant ID: YOUR-TENANT-ID
→ Client ID: YOUR-CLIENT-ID
→ Auth method: device-code
```

#### 1.2 List Tenants
```bash
ctl365 tenant list --detailed
```

**Expected Output:**
```
Configured Tenants:

• test-tenant (active)
  Tenant ID: YOUR-TENANT-ID
  Client ID: YOUR-CLIENT-ID
  Auth: Device Code Flow
  Description: Testing tenant for ctl365
```

#### 1.3 Login
```bash
ctl365 login
```

**Expected Behavior:**
1. Displays device code (e.g., `A1B2C3D4`)
2. Shows URL: `https://microsoft.com/devicelogin`
3. Prompts you to open browser and enter code
4. After authentication, shows success message

**Expected Output:**
```
Authenticating to tenant: test-tenant

→ Opening browser for device code authentication...
→ If browser doesn't open, visit: https://microsoft.com/devicelogin
→ Enter code: A1B2C3D4

✓ Authentication successful
✓ Token cached to: ~/.ctl365/cache/test-tenant.token
```

**Verification:**
```bash
# Check token file was created
ls -la ~/.ctl365/cache/
```

---

### Phase 2: Windows Baseline Testing (30 min)

#### 2.1 List Available Templates
```bash
ctl365 baseline list
```

**Expected Output:** Should show all platforms (Windows, macOS, iOS, Android) with OIB templates marked as PRODUCTION-READY

#### 2.2 Generate Windows Baseline (Dry Run)
```bash
ctl365 baseline new windows \
  --template oib \
  --encryption \
  --defender \
  --output test-windows-baseline.json
```

**Expected Output:**
```
Generating Windows baseline configuration...

✓ Baseline saved to: test-windows-baseline.json

Baseline Summary:
  Platform: windows
  Policies: 15
  ✓ Encryption enabled
  ✓ Defender for Endpoint enabled
```

**Verification:**
```bash
# Check the JSON file was created
cat test-windows-baseline.json | jq '.metadata'
```

#### 2.3 Validate Baseline JSON
```bash
# Count policies
cat test-windows-baseline.json | jq '.policies | length'

# Expected: 15 or more

# Check policy types
cat test-windows-baseline.json | jq '.policies[].["@odata.type"]' | sort | uniq
```

**Expected Policy Types:**
```json
"#microsoft.graph.windows10CompliancePolicy"
"#microsoft.graph.windows10CustomConfiguration"
"#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration"
```

#### 2.4 Apply Baseline (DRY RUN - Safe)

⚠️ **IMPORTANT**: Start with `--dry-run` to preview changes!

```bash
ctl365 baseline apply \
  --file test-windows-baseline.json \
  --dry-run
```

**Expected Output:**
```
Applying baseline from: test-windows-baseline.json

→ Active tenant: test-tenant

DRY RUN (no policies created)

  → would create: Baseline - Windows Compliance
  → would create: Baseline - BitLocker Configuration
  → would create: Baseline - Defender Settings
  ...
```

#### 2.5 Apply Baseline (REAL - Be Careful!)

⚠️ **ONLY if dry run looks good AND you're OK creating policies in tenant**

```bash
ctl365 baseline apply \
  --file test-windows-baseline.json \
  --yes
```

**Expected Output:**
```
Applying baseline from: test-windows-baseline.json

→ Active tenant: test-tenant

? Apply 15 policies to tenant 'test-tenant'? [y/N]: y

Deploying policies...

  → Creating: Baseline - Windows Compliance... ✓
  → Creating: Baseline - BitLocker Configuration... ✓
  ...

✓ Successfully deployed 15 policies
```

**Verification in Intune:**
1. Open https://intune.microsoft.com
2. Go to **Devices** → **Compliance policies**
3. Should see "Baseline - Windows Compliance" (or similar)
4. Go to **Devices** → **Configuration profiles**
5. Should see other baseline policies

---

### Phase 3: Other Platforms (20 min each)

#### 3.1 macOS Baseline
```bash
# Generate
ctl365 baseline new macos --template oib --encryption -o test-macos.json

# Preview
cat test-macos.json | jq '.metadata'

# Apply (dry run first!)
ctl365 baseline apply --file test-macos.json --dry-run
```

#### 3.2 iOS Baseline
```bash
# Generate
ctl365 baseline new ios --template oib --defender --min-os 17.0 -o test-ios.json

# Preview
cat test-ios.json | jq '.policies | length'

# Apply (dry run first!)
ctl365 baseline apply --file test-ios.json --dry-run
```

#### 3.3 Android Baseline
```bash
# Generate
ctl365 baseline new android --template oib --defender -o test-android.json

# Preview
cat test-android.json | jq '.metadata'

# Apply (dry run first!)
ctl365 baseline apply --file test-android.json --dry-run
```

---

### Phase 4: Conditional Access (30 min)

⚠️ **CRITICAL WARNING**: CA policies affect user access. Test in non-production tenant!

#### 4.1 List CA Policy Templates
```bash
# View available CA policies
cat src/templates/ca_baseline_2025.rs | grep "fn ca"
```

#### 4.2 Deploy CA Policies (Report-Only Mode)

**Best Practice**: Deploy in report-only mode first!

```bash
ctl365 ca deploy \
  --baseline 2025 \
  --report-only
```

**Expected Behavior:**
- Creates all 44 CA policies
- Sets state to "enabledForReportingButNotEnforced"
- No users are actually blocked/required MFA yet
- Can review impact in Azure AD sign-in logs

**Verification:**
1. Open https://entra.microsoft.com
2. Go to **Protection** → **Conditional Access**
3. Should see 44 policies prefixed with "CAD", "CAL", "CAP", "CAR", "CAS", "CAU"
4. All should be in "Report-only" mode

#### 4.3 Review Impact (Wait 24-48 hours)
```bash
# After policies run in report-only mode, check sign-in logs
# Entra → Sign-ins → Conditional Access tab
```

---

### Phase 5: Autopilot (45 min)

#### 5.1 Create Test CSV
```bash
cat > test-autopilot.csv << 'EOF'
Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Assigned User
TEST001,00000-00000-00000-00000,BASE64HASH==,test-devices,user@domain.com
EOF
```

**Note**: You need actual hardware hashes from devices. Get them via:
```powershell
# On Windows device:
Get-WindowsAutopilotInfo -OutputFile autopilot-hash.csv
```

#### 5.2 Import Devices
```bash
ctl365 autopilot import \
  --file test-autopilot.csv \
  --group-tag "test-import"
```

#### 5.3 Create Autopilot Profile
```bash
ctl365 autopilot profile \
  --name "Test Standard Deployment" \
  --mode user-driven \
  --skip-keyboard \
  --skip-privacy \
  --skip-eula
```

#### 5.4 List Devices
```bash
ctl365 autopilot list --detailed
```

---

### Phase 6: Application Deployment (30 min)

#### 6.1 Deploy Microsoft 365 Apps
```bash
ctl365 app deploy-m365 \
  --name "Microsoft 365 Apps for Enterprise" \
  --suite enterprise \
  --architecture x64 \
  --channel monthlyEnterprise \
  --apps "outlook,word,excel,powerpoint,teams" \
  --assign-to-all
```

#### 6.2 List Deployed Apps
```bash
ctl365 app list --platform windows
```

---

### Phase 7: Export/Import Testing (30 min)

#### 7.1 Export Current Configuration
```bash
ctl365 export export \
  --types all \
  --include-assignments \
  --output export-backup/
```

**Expected Output:**
```
Exporting policies from tenant: test-tenant

→ Compliance Policies...
  ✓ Exported: Baseline - Windows Compliance

→ Configuration Profiles...
  ✓ Exported: Baseline - BitLocker Configuration

...

✓ Export complete: 23 policies saved to export-backup/
```

#### 7.2 Import to Another Tenant (Dry Run)
```bash
# Switch to different tenant
ctl365 tenant switch another-tenant

# Import (dry run)
ctl365 export import \
  --directory export-backup/ \
  --skip-existing \
  --dry-run
```

---

### Phase 8: Audit & Drift Detection (20 min)

#### 8.1 Check Drift from Baseline
```bash
ctl365 audit drift \
  --baseline test-windows-baseline.json \
  --detailed
```

**Expected Output:**
```
Checking configuration drift...

→ Comparing baseline vs tenant configuration

Drift Summary:
  Missing policies: 0
  Modified policies: 2
  Extra policies: 1

Modified Policies:
  • Baseline - Windows Compliance
    - osMinimumVersion: "10.0.26100.0" → "10.0.22631.0"

Extra Policies (not in baseline):
  • Manual Test Policy (manually created)
```

#### 8.2 Auto-Remediate Drift
```bash
ctl365 audit drift \
  --baseline test-windows-baseline.json \
  --fix \
  --dry-run
```

#### 8.3 Generate Compliance Report
```bash
ctl365 audit check \
  --output html \
  --output-file compliance-report.html
```

---

## 🐛 Common Issues & Solutions

### Issue: "No active tenant"
```bash
# Solution:
ctl365 tenant switch test-tenant
```

### Issue: "Authentication failed"
```bash
# Solution: Clear cache and re-login
rm ~/.ctl365/cache/test-tenant.token
ctl365 login
```

### Issue: "Insufficient privileges"
```bash
# Solution: Check app registration permissions
# - Go to Azure AD → App registrations → API permissions
# - Ensure admin consent granted (green checkmarks)
```

### Issue: "Policy already exists"
```bash
# Solution: Use different name or delete existing policy
ctl365 baseline apply --file test.json --skip-existing
```

---

## ✅ Success Criteria

After completing all phases, you should have:

- [x] Successfully authenticated to tenant
- [x] Generated baselines for all 4 platforms
- [x] Applied at least Windows baseline (policies visible in Intune)
- [x] Deployed Conditional Access policies (report-only mode)
- [x] Imported Autopilot device(s)
- [x] Created Autopilot profile
- [x] Deployed Microsoft 365 Apps
- [x] Exported policies to JSON
- [x] Run drift detection
- [x] Generated compliance report

---

## 📊 Testing Checklist

Copy this checklist and check off as you test:

```markdown
## Authentication
- [ ] `ctl365 tenant add` works
- [ ] `ctl365 login` device code flow works
- [ ] Token cached correctly
- [ ] `ctl365 tenant list` shows tenant

## Windows Baseline
- [ ] `ctl365 baseline new windows --template oib` generates JSON
- [ ] JSON contains 15+ policies
- [ ] `--dry-run` shows preview without creating policies
- [ ] Real apply creates policies in Intune
- [ ] Policies visible in Intune portal

## Other Platforms
- [ ] macOS baseline generates successfully
- [ ] iOS baseline generates successfully
- [ ] Android baseline generates successfully

## Conditional Access
- [ ] CA deployment creates 44 policies
- [ ] All policies in "Report-only" mode
- [ ] Policies visible in Entra portal

## Autopilot
- [ ] CSV import works
- [ ] Profile creation works
- [ ] Device listing works
- [ ] Devices visible in Intune → Devices → Enroll devices → Windows enrollment → Devices

## Application Deployment
- [ ] M365 Apps deployment works
- [ ] App listing works
- [ ] App visible in Intune portal

## Export/Import
- [ ] Export creates JSON files
- [ ] Import dry-run shows preview
- [ ] Real import creates policies

## Audit
- [ ] Drift detection identifies changes
- [ ] Compliance report generates
- [ ] Auto-fix creates missing policies

## Error Handling
- [ ] Invalid credentials shows clear error
- [ ] Missing permissions shows helpful message
- [ ] Network failures handled gracefully
```

---

## 🎯 Next Steps After Testing

1. **Document Bugs**: Create GitHub issues for any failures
2. **Performance Notes**: Record how long each operation takes
3. **UX Feedback**: Note any confusing messages or missing features
4. **Production Readiness**: Update ROADMAP.md with blockers found

---

**Ready to start testing!** 🚀

Begin with Phase 1 (Authentication) and work through sequentially.
