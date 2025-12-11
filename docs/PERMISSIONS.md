# Microsoft Graph API Permissions Reference

This document provides a comprehensive reference for all Microsoft Graph API permissions required by ctl365 commands.

---

## Quick Reference

### Minimum Required (Core Commands)

```
DeviceManagementConfiguration.ReadWrite.All     # Baselines, Settings Catalog
DeviceManagementManagedDevices.ReadWrite.All    # Device management
Policy.ReadWrite.ConditionalAccess              # CA policies
Directory.Read.All                               # Read directory info
Group.Read.All                                   # Read groups
```

### Full Feature Set

```
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementApps.ReadWrite.All
DeviceManagementManagedDevices.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
Directory.ReadWrite.All
Group.ReadWrite.All
Policy.ReadWrite.ConditionalAccess
Sites.FullControl.All                           # SharePoint
User.Read.All                                   # Viva Engage
ExternalConnection.ReadWrite.OwnedBy            # Copilot
Mail.Read                                       # Copilot
```

---

## Permissions by Command

### Authentication (`login`, `tenant`)

| Permission | Type | Required |
|------------|------|----------|
| `User.Read` | Delegated | Yes |
| `offline_access` | Delegated | Yes (for refresh tokens) |

### Baselines (`baseline new`, `baseline apply`)

| Permission | Type | Required |
|------------|------|----------|
| `DeviceManagementConfiguration.ReadWrite.All` | Both | Yes |
| `DeviceManagementManagedDevices.ReadWrite.All` | Both | Yes |
| `Group.Read.All` | Both | For group assignments |

### Conditional Access (`ca deploy`, `ca list`)

| Permission | Type | Required |
|------------|------|----------|
| `Policy.ReadWrite.ConditionalAccess` | Both | Yes |
| `Policy.Read.All` | Both | For list only |
| `Directory.Read.All` | Both | For named locations |

### Application Deployment (`app deploy`, `app list`)

| Permission | Type | Required |
|------------|------|----------|
| `DeviceManagementApps.ReadWrite.All` | Both | Yes |
| `Group.Read.All` | Both | For assignments |

### Autopilot (`autopilot import`, `autopilot profile`)

| Permission | Type | Required |
|------------|------|----------|
| `DeviceManagementServiceConfig.ReadWrite.All` | Both | Yes |
| `DeviceManagementManagedDevices.ReadWrite.All` | Both | Yes |
| `Group.ReadWrite.All` | Both | For group tags |

### Export/Import (`export export`, `export import`)

| Permission | Type | Required |
|------------|------|----------|
| `DeviceManagementConfiguration.ReadWrite.All` | Both | Yes |
| `DeviceManagementApps.ReadWrite.All` | Both | Yes |
| `Policy.ReadWrite.ConditionalAccess` | Both | For CA policies |
| `Group.ReadWrite.All` | Both | For assignment migration |

### Audit (`audit check`, `audit drift`)

| Permission | Type | Required |
|------------|------|----------|
| `DeviceManagementConfiguration.Read.All` | Both | Yes |
| `DeviceManagementManagedDevices.Read.All` | Both | Yes |
| `DeviceManagementConfiguration.ReadWrite.All` | Both | For --fix |

### SharePoint (`sharepoint site-*`, `sharepoint hub-*`)

| Permission | Type | Required |
|------------|------|----------|
| `Sites.FullControl.All` | Both | Yes |
| `Sites.ReadWrite.All` | Both | Alternative (less privileged) |

### Viva Engage (`viva community-*`, `viva role-*`)

| Permission | Type | Required |
|------------|------|----------|
| `Community.ReadWrite.All` | Application | Yes |
| `User.Read.All` | Both | For member lookup |

### Copilot (`copilot agents-*`, `copilot search`)

| Permission | Type | Required |
|------------|------|----------|
| `ExternalConnection.ReadWrite.OwnedBy` | Application | For agents |
| `Files.Read.All` | Delegated | For search |
| `Mail.Read` | Delegated | For search |

### SCuBA (`scuba audit`, `scuba status`)

| Permission | Type | Required |
|------------|------|----------|
| `SecurityEvents.Read.All` | Both | Yes |
| `Policy.Read.All` | Both | Yes |
| `AuditLog.Read.All` | Both | Yes |

### Security Monitoring (TUI - Identity Protection)

View sign-in logs, risky users, risky sign-ins, and directory audit logs. Some features require Entra ID P1/P2 licensing.

| Permission | Type | Required |
|------------|------|----------|
| `AuditLog.Read.All` | Both | Sign-in logs, directory audit |
| `IdentityRiskyUser.Read.All` | Both | Risky users (read-only) |
| `IdentityRiskyUser.ReadWrite.All` | Both | Dismiss/confirm risky users |
| `IdentityRiskEvent.Read.All` | Both | Risky sign-ins |

**Note:** Risky user and risky sign-in data requires **Entra ID P1 or P2** licensing. Without P1/P2, the API will return empty results.

---

## Permission Types

### Delegated Permissions

Used with **Device Code Flow** (interactive login).

- Requires user to sign in
- Permissions apply in context of signed-in user
- User must have appropriate Intune/Azure AD role
- Best for: Interactive CLI use, testing, development

### Application Permissions

Used with **Client Credentials Flow** (automated).

- No user sign-in required
- App acts as itself (service principal)
- Requires admin consent
- Best for: CI/CD, scheduled tasks, automation

---

## Azure AD Roles Required

In addition to API permissions, the signed-in user (for delegated flow) needs appropriate Azure AD roles:

| Role | Required For |
|------|-------------|
| **Intune Administrator** | All Intune operations |
| **Conditional Access Administrator** | CA policy management |
| **Global Administrator** | Full access (not recommended for daily use) |
| **Security Administrator** | Read-only security operations |
| **Exchange Administrator** | Exchange Online configuration |
| **SharePoint Administrator** | SharePoint site management |

---

## Granting Admin Consent

### Azure Portal Method

1. Navigate to **Azure AD > App registrations > Your App > API permissions**
2. Click **Grant admin consent for [Your Tenant]**
3. Confirm the consent dialog

### PowerShell Method

```powershell
# Connect to Azure AD
Connect-AzureAD

# Get the service principal
$sp = Get-AzureADServicePrincipal -Filter "displayName eq 'ctl365-automation'"

# Grant consent (example for one permission)
New-AzureADServiceAppRoleAssignment `
  -ObjectId $sp.ObjectId `
  -PrincipalId $sp.ObjectId `
  -ResourceId (Get-AzureADServicePrincipal -Filter "displayName eq 'Microsoft Graph'").ObjectId `
  -Id "9241abd9-d0e6-425a-bd4f-47ba86e767a4"  # DeviceManagementConfiguration.ReadWrite.All
```

### Microsoft Graph PowerShell Method

```powershell
# Connect with admin privileges
Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"

# Get app registration
$app = Get-MgApplication -Filter "displayName eq 'ctl365-automation'"

# Get Microsoft Graph service principal
$graphSp = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"

# Add required permission
$params = @{
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = @(
                @{
                    Id = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"  # DeviceManagementConfiguration.ReadWrite.All
                    Type = "Role"
                }
            )
        }
    )
}
Update-MgApplication -ApplicationId $app.Id -BodyParameter $params
```

---

## Troubleshooting Permission Errors

### 403 Forbidden / Insufficient Privileges

```
Error: Authorization_RequestDenied - Insufficient privileges
```

**Check:**
1. Required permission is added to app registration
2. Admin consent has been granted
3. User has appropriate Azure AD role
4. Using correct authentication flow for permission type

### Missing Scope in Token

```
Error: Missing scope for operation
```

**Fix:**
```bash
# Re-authenticate to get new token with updated scopes
ctl365 logout
ctl365 login --tenant my-tenant
```

### Consent Not Granted

```
Error: AADSTS65001 - User has not consented
```

**Fix:**
- Grant admin consent in Azure Portal, or
- Have user consent during login (delegated permissions only)

---

## Permission IDs Reference

| Permission | GUID |
|------------|------|
| AuditLog.Read.All | b0afded3-3588-46d8-8b3d-9842eff778da |
| DeviceManagementApps.ReadWrite.All | 78145de6-330d-4800-a6ce-494ff2d33d07 |
| DeviceManagementConfiguration.ReadWrite.All | 9241abd9-d0e6-425a-bd4f-47ba86e767a4 |
| DeviceManagementManagedDevices.ReadWrite.All | 243333ab-4d21-40cb-a475-36241daa0842 |
| DeviceManagementServiceConfig.ReadWrite.All | 5ac13192-7ace-4fcf-b828-1a26f28068ee |
| Directory.ReadWrite.All | 19dbc75e-c2e2-444c-a770-ec69d8559fc7 |
| Group.ReadWrite.All | 62a82d76-70ea-41e2-9197-370581804d09 |
| IdentityRiskEvent.Read.All | db06fb33-1953-4b7b-a9d4-f6f2b14b9e4e |
| IdentityRiskyUser.Read.All | dc5007c0-2d7d-4c42-879c-2dab87571379 |
| IdentityRiskyUser.ReadWrite.All | 656f6061-f9fe-4807-9708-6a2e0934df76 |
| Policy.ReadWrite.ConditionalAccess | ad902697-1014-4ef5-81ef-2b4301988e8c |
| Sites.FullControl.All | a82116e5-55eb-4c41-a434-62fe8a61c773 |

---

## See Also

- [App Registration Setup](APP_REGISTRATION.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
