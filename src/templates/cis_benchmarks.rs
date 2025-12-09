//! CIS Benchmark Templates for Windows 10/11
//!
//! Implements Center for Internet Security (CIS) Benchmark controls for Intune.
//! Based on CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0
//!
//! Levels:
//! - Level 1 (L1): Essential security settings, broadly applicable
//! - Level 2 (L2): Defense-in-depth, may impact functionality
//! - BitLocker (BL): Additional BitLocker hardening
//!
//! Reference: https://www.cisecurity.org/benchmark/microsoft_windows_desktop

#![allow(dead_code)]

use serde_json::{json, Value};

/// CIS Benchmark Level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CisLevel {
    Level1,
    Level2,
    BitLocker,
}

/// Generate CIS Level 1 baseline (Essential security)
pub fn generate_cis_level1(name_prefix: &str) -> Vec<Value> {
    let mut policies = Vec::new();

    // Account Policies - Password Policy (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L1 Password Policy", name_prefix),
        "description": "CIS Level 1 - Account Policies: Password Settings",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.1.1 (L1) Password History",
                "description": "Enforce password history: 24 or more passwords",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordHistory",
                "value": 24
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.1.2 (L1) Maximum Password Age",
                "description": "Maximum password age: 365 or fewer days",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxDevicePasswordAgeDays",
                "value": 60
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.1.3 (L1) Minimum Password Age",
                "description": "Minimum password age: 1 or more days",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordAge",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.1.4 (L1) Minimum Password Length",
                "description": "Minimum password length: 14 or more characters",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength",
                "value": 14
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.1.5 (L1) Password Complexity",
                "description": "Password must meet complexity requirements",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordComplexity",
                "value": 1
            }
        ]
    }));

    // Account Lockout Policy (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L1 Account Lockout", name_prefix),
        "description": "CIS Level 1 - Account Lockout Policy",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.2.1 (L1) Account Lockout Duration",
                "description": "Account lockout duration: 15 or more minutes",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/AccountLockoutDuration",
                "value": 15
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.2.2 (L1) Account Lockout Threshold",
                "description": "Account lockout threshold: 5 or fewer invalid attempts",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxDevicePasswordFailedAttempts",
                "value": 5
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "1.2.3 (L1) Reset Account Lockout Counter",
                "description": "Reset account lockout counter after: 15 or more minutes",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/AccountLockoutCounterResetTime",
                "value": 15
            }
        ]
    }));

    // Windows Defender Antivirus (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
        "displayName": format!("{} - CIS L1 Defender Antivirus", name_prefix),
        "description": "CIS Level 1 - Windows Defender Antivirus settings",
        "defenderBlockOnPotentiallyUnwantedApps": "enable",
        "defenderCloudBlockLevel": "high",
        "defenderCloudExtendedTimeoutInSeconds": 50,
        "defenderDaysBeforeDeletingQuarantinedMalware": 14,
        "defenderDetectedMalwareActions": {
            "lowSeverity": "clean",
            "moderateSeverity": "quarantine",
            "highSeverity": "remove",
            "severeSeverity": "remove"
        },
        "defenderRealTimeMonitor": "enable",
        "defenderScanArchiveFiles": true,
        "defenderScanDownloads": true,
        "defenderScanIncomingMail": true,
        "defenderScanMappedNetworkDrivesDuringFullScan": false,
        "defenderScanNetworkFiles": true,
        "defenderScanRemovableDrivesDuringFullScan": true,
        "defenderScanScriptsLoadedInInternetExplorer": true,
        "defenderScanType": "full",
        "defenderScheduledQuickScanTime": "12:00:00.0000000",
        "defenderScheduledScanTime": "02:00:00.0000000",
        "defenderSignatureUpdateIntervalInHours": 4,
        "defenderSubmitSamplesConsentType": "sendSafeSamplesAutomatically"
    }));

    // Windows Defender Firewall (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
        "displayName": format!("{} - CIS L1 Firewall", name_prefix),
        "description": "CIS Level 1 - Windows Firewall settings",
        "firewallBlockStatefulFTP": true,
        "firewallCertificateRevocationListCheckMethod": "deviceDefault",
        "firewallIdleTimeoutForSecurityAssociationInSeconds": 300,
        "firewallIPSecExemptionsAllowDHCP": false,
        "firewallIPSecExemptionsAllowICMP": false,
        "firewallIPSecExemptionsAllowNeighborDiscovery": false,
        "firewallIPSecExemptionsAllowRouterDiscovery": false,
        "firewallMergeKeyingModuleSettings": true,
        "firewallPacketQueueingMethod": "deviceDefault",
        "firewallPreSharedKeyEncodingMethod": "deviceDefault",
        "firewallProfileDomain": {
            "firewallEnabled": "allowed",
            "inboundNotificationsBlocked": true,
            "incomingTrafficBlocked": true,
            "outgoingTrafficBlocked": false,
            "stealthModeBlocked": false,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "globalPortRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyMerged": true,
            "inboundConnectionsBlocked": true,
            "authorizedApplicationRulesFromGroupPolicyMerged": true
        },
        "firewallProfilePrivate": {
            "firewallEnabled": "allowed",
            "inboundNotificationsBlocked": true,
            "incomingTrafficBlocked": true,
            "outgoingTrafficBlocked": false,
            "stealthModeBlocked": false,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "globalPortRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyMerged": true,
            "inboundConnectionsBlocked": true,
            "authorizedApplicationRulesFromGroupPolicyMerged": true
        },
        "firewallProfilePublic": {
            "firewallEnabled": "allowed",
            "inboundNotificationsBlocked": true,
            "incomingTrafficBlocked": true,
            "outgoingTrafficBlocked": false,
            "stealthModeBlocked": false,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "globalPortRulesFromGroupPolicyMerged": false,
            "connectionSecurityRulesFromGroupPolicyMerged": false,
            "inboundConnectionsBlocked": true,
            "authorizedApplicationRulesFromGroupPolicyMerged": false
        }
    }));

    // SmartScreen and Exploit Protection (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
        "displayName": format!("{} - CIS L1 SmartScreen & Exploit Protection", name_prefix),
        "description": "CIS Level 1 - SmartScreen and Exploit Protection",
        "smartScreenBlockOverrideForFiles": true,
        "smartScreenEnableInShell": true,
        "applicationGuardBlockClipboardSharing": "blockAll",
        "applicationGuardBlockFileTransfer": "blockAll",
        "applicationGuardBlockNonEnterpriseContent": true,
        "applicationGuardEnabled": true,
        "applicationGuardEnabledOptions": "enabledForEdge",
        "applicationGuardForceAuditing": true,
        "defenderAdobeReaderLaunchChildProcess": "enable",
        "defenderAdvancedRansomwareProtectionType": "enable",
        "defenderBlockPersistenceThroughWmiType": "block",
        "defenderEmailContentExecution": "block",
        "defenderEmailContentExecutionType": "block",
        "defenderGuardMyFoldersType": "enable",
        "defenderGuardedFoldersAllowedAppPaths": [],
        "defenderNetworkProtectionType": "enable",
        "defenderOfficeAppsExecutableContentCreationOrLaunch": "block",
        "defenderOfficeAppsExecutableContentCreationOrLaunchType": "block",
        "defenderOfficeAppsLaunchChildProcess": "block",
        "defenderOfficeAppsLaunchChildProcessType": "block",
        "defenderOfficeAppsOtherProcessInjection": "block",
        "defenderOfficeAppsOtherProcessInjectionType": "block",
        "defenderOfficeCommunicationAppsLaunchChildProcess": "enable",
        "defenderOfficeMacroCodeAllowWin32Imports": "block",
        "defenderOfficeMacroCodeAllowWin32ImportsType": "block",
        "defenderPreventCredentialStealingType": "enable",
        "defenderProcessCreation": "block",
        "defenderProcessCreationType": "block",
        "defenderScriptDownloadedPayloadExecution": "block",
        "defenderScriptDownloadedPayloadExecutionType": "block",
        "defenderScriptObfuscatedMacroCode": "block",
        "defenderScriptObfuscatedMacroCodeType": "block",
        "defenderUntrustedExecutable": "block",
        "defenderUntrustedExecutableType": "block",
        "defenderUntrustedUSBProcess": "block",
        "defenderUntrustedUSBProcessType": "block"
    }));

    // Local Policies - Security Options (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L1 Security Options", name_prefix),
        "description": "CIS Level 1 - Local Policies: Security Options",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "2.3.1.1 (L1) Administrator Account Status",
                "description": "Accounts: Administrator account status - Disabled",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_EnableAdministratorAccountStatus",
                "value": 0
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "2.3.1.2 (L1) Guest Account Status",
                "description": "Accounts: Guest account status - Disabled",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_EnableGuestAccountStatus",
                "value": 0
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "2.3.7.1 (L1) Interactive Logon Machine Inactivity Limit",
                "description": "Interactive logon: Machine inactivity limit - 900 seconds",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit",
                "value": 900
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "2.3.11.1 (L1) Network Security LAN Manager Auth Level",
                "description": "Network security: LAN Manager authentication level - NTLMv2 only",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_LANManagerAuthenticationLevel",
                "value": 5
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "2.3.11.2 (L1) Network Security Minimum Session Security for NTLM SSP",
                "description": "Require NTLMv2 session security for clients",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedClients",
                "value": 537395200
            }
        ]
    }));

    // User Rights Assignment (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L1 User Rights", name_prefix),
        "description": "CIS Level 1 - User Rights Assignment",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "2.2.1 (L1) Access Credential Manager",
                "description": "Access Credential Manager as a trusted caller - No one",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/UserRights/AccessCredentialManagerAsTrustedCaller",
                "value": ""
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "2.2.3 (L1) Act as Part of OS",
                "description": "Act as part of the operating system - No one",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/UserRights/ActAsPartOfTheOperatingSystem",
                "value": ""
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "2.2.6 (L1) Allow Log on Locally",
                "description": "Allow log on locally - Administrators, Users",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/UserRights/AllowLocalLogOn",
                "value": "*S-1-5-32-544;*S-1-5-32-545"
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "2.2.8 (L1) Create Global Objects",
                "description": "Create global objects - Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/UserRights/CreateGlobalObjects",
                "value": "*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6"
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "2.2.11 (L1) Debug Programs",
                "description": "Debug programs - Administrators",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/UserRights/DebugPrograms",
                "value": "*S-1-5-32-544"
            }
        ]
    }));

    // Audit Policy (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L1 Audit Policy", name_prefix),
        "description": "CIS Level 1 - Advanced Audit Policy Configuration",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.1.1 (L1) Audit Credential Validation",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogon_AuditCredentialValidation",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.2.1 (L1) Audit Application Group Management",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditApplicationGroupManagement",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.2.2 (L1) Audit Security Group Management",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditSecurityGroupManagement",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.2.3 (L1) Audit User Account Management",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditUserAccountManagement",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.5.1 (L1) Audit Account Lockout",
                "description": "Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/LogonLogoff_AuditAccountLockout",
                "value": 2
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.5.2 (L1) Audit Group Membership",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/LogonLogoff_AuditGroupMembership",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.5.3 (L1) Audit Logon",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/LogonLogoff_AuditLogon",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.6.1 (L1) Audit Detailed File Share",
                "description": "Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditDetailedFileShare",
                "value": 2
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.7.1 (L1) Audit Audit Policy Change",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuditPolicyChange",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.9.1 (L1) Audit Security State Change",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSecurityStateChange",
                "value": 1
            }
        ]
    }));

    // Windows Components (L1)
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
        "displayName": format!("{} - CIS L1 Windows Components", name_prefix),
        "description": "CIS Level 1 - Windows Components settings",
        "defenderPotentiallyUnwantedAppAction": "block",
        "defenderScanMaxCpu": 50,
        "passwordBlockSimple": true,
        "passwordRequired": true,
        "passwordRequiredType": "deviceDefault",
        "searchDisableAutoLanguageDetection": false,
        "settingsBlockAccountsPage": false,
        "settingsBlockAddProvisioningPackage": true,
        "settingsBlockRemoveProvisioningPackage": true,
        "windowsSpotlightBlockOnActionCenter": true,
        "windowsSpotlightBlockTailoredExperiences": true,
        "windowsSpotlightBlockThirdPartyNotifications": true,
        "windowsSpotlightBlocked": true,
        "windowsSpotlightBlockWelcomeExperience": true,
        "windowsSpotlightBlockWindowsTips": true,
        "storageBlockRemovableStorage": false,
        "usbBlocked": false
    }));

    policies
}

/// Generate CIS Level 2 baseline (Defense-in-depth)
pub fn generate_cis_level2(name_prefix: &str) -> Vec<Value> {
    // Start with L1 policies
    let mut policies = generate_cis_level1(name_prefix);

    // Add L2-specific hardening
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L2 Enhanced Security", name_prefix),
        "description": "CIS Level 2 - Enhanced security settings (may impact functionality)",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.4.1 (L2) MSS Legacy IPv6 Source Routing",
                "description": "MSS: (DisableIPSourceRouting IPv6) Highest protection",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel",
                "value": 2
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.4.2 (L2) MSS Legacy IP Source Routing",
                "description": "MSS: (DisableIPSourceRouting) Highest protection",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
                "value": 2
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.4.3 (L2) MSS Legacy Allow ICMP Redirects",
                "description": "Disable ICMP redirects override OSPF routes",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
                "value": 0
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.5.1 (L2) NetBIOS Node Type",
                "description": "Set NetBIOS to P-node (point-to-point)",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSS/NetBIOSNodeType",
                "value": 2
            }
        ]
    }));

    // L2 Remote Desktop hardening
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L2 Remote Desktop Hardening", name_prefix),
        "description": "CIS Level 2 - Remote Desktop security settings",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.9.52.3.9.1 (L2) Always Prompt for Password on Connection",
                "description": "Require password on RDP connection",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/ClientConnectionEncryptionLevel",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.9.52.3.9.2 (L2) RDP Encryption Level",
                "description": "Set client connection encryption level to High",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.9.52.3.11.1 (L2) Do Not Allow COM Port Redirection",
                "description": "Disable COM port redirection in RDP",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowCOMPortRedirection",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.9.52.3.11.2 (L2) Do Not Allow LPT Port Redirection",
                "description": "Disable LPT port redirection in RDP",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowLPTPortRedirection",
                "value": 1
            }
        ]
    }));

    // L2 Network settings
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L2 Network Hardening", name_prefix),
        "description": "CIS Level 2 - Network security hardening",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.5.11.2 (L2) Prohibit Installation on Remote Print Queue",
                "description": "Prohibit installation of printers over HTTP",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.5.14.1 (L2) Hardened UNC Paths NETLOGON",
                "description": "Require mutual auth and integrity for NETLOGON share",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "18.8.22.1.1 (L2) Turn on Mapper I/O Driver",
                "description": "Disable LLTD I/O Driver",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons",
                "value": 0
            }
        ]
    }));

    // L2 Enhanced Audit
    policies.push(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - CIS L2 Enhanced Audit", name_prefix),
        "description": "CIS Level 2 - Additional audit settings",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.3.1 (L2) Audit PNP Activity",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditPNPActivity",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.3.2 (L2) Audit Process Creation",
                "description": "Success",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditProcessCreation",
                "value": 1
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.6.2 (L2) Audit File Share",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditFileShare",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.6.3 (L2) Audit Other Object Access Events",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditOtherObjectAccessEvents",
                "value": 3
            },
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "17.6.4 (L2) Audit Removable Storage",
                "description": "Success and Failure",
                "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditRemovableStorage",
                "value": 3
            }
        ]
    }));

    policies
}

/// Generate CIS BitLocker recommendations
pub fn generate_cis_bitlocker(name_prefix: &str) -> Vec<Value> {
    vec![
        json!({
            "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
            "displayName": format!("{} - CIS BitLocker Configuration", name_prefix),
            "description": "CIS Benchmark - BitLocker Drive Encryption",
            "bitLockerAllowStandardUserEncryption": true,
            "bitLockerDisableWarningForOtherDiskEncryption": true,
            "bitLockerEnableStorageCardEncryptionOnMobile": false,
            "bitLockerEncryptDevice": true,
            "bitLockerRecoveryPasswordRotation": "enabledForAzureAd",
            "bitLockerSystemDrivePolicy": {
                "encryptionMethod": "xtsAes256",
                "minimumPinLength": 6,
                "prebootRecoveryEnableMessageAndUrl": true,
                "recoveryOptions": {
                    "blockDataRecoveryAgent": true,
                    "enableBitLockerAfterRecoveryInformationToStore": "passwordAndKey",
                    "enableRecoveryInformationSaveToStore": true,
                    "hideRecoveryOptions": true,
                    "recoveryInformationToStore": "passwordAndKey",
                    "recoveryKeyUsage": "allowed",
                    "recoveryPasswordUsage": "allowed"
                },
                "startupAuthenticationBlockWithoutTpmChip": true,
                "startupAuthenticationRequired": true,
                "startupAuthenticationTpmKeyUsage": "allowed",
                "startupAuthenticationTpmPinAndKeyUsage": "allowed",
                "startupAuthenticationTpmPinUsage": "required",
                "startupAuthenticationTpmUsage": "required"
            },
            "bitLockerFixedDrivePolicy": {
                "encryptionMethod": "xtsAes256",
                "recoveryOptions": {
                    "blockDataRecoveryAgent": true,
                    "enableBitLockerAfterRecoveryInformationToStore": "passwordAndKey",
                    "enableRecoveryInformationSaveToStore": true,
                    "hideRecoveryOptions": true,
                    "recoveryInformationToStore": "passwordAndKey",
                    "recoveryKeyUsage": "allowed",
                    "recoveryPasswordUsage": "allowed"
                },
                "requireEncryptionForWriteAccess": true
            },
            "bitLockerRemovableDrivePolicy": {
                "blockCrossOrganizationWriteAccess": true,
                "encryptionMethod": "aesCbc256",
                "requireEncryptionForWriteAccess": true
            }
        })
    ]
}

/// Generate complete CIS baseline (L1 + L2 + BitLocker)
pub fn generate_cis_full_baseline(name_prefix: &str, level: CisLevel) -> Vec<Value> {
    match level {
        CisLevel::Level1 => generate_cis_level1(name_prefix),
        CisLevel::Level2 => generate_cis_level2(name_prefix),
        CisLevel::BitLocker => {
            let mut policies = generate_cis_level2(name_prefix);
            policies.extend(generate_cis_bitlocker(name_prefix));
            policies
        }
    }
}

/// Get CIS control description for documentation
pub fn get_cis_control_info(control_id: &str) -> Option<CisControlInfo> {
    let controls: Vec<(&str, CisControlInfo)> = vec![
        ("1.1.1", CisControlInfo {
            title: "Ensure 'Enforce password history' is set to '24 or more password(s)'".into(),
            level: CisLevel::Level1,
            description: "This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password.".into(),
            rationale: "The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute force attacks.".into(),
        }),
        ("1.1.4", CisControlInfo {
            title: "Ensure 'Minimum password length' is set to '14 or more character(s)'".into(),
            level: CisLevel::Level1,
            description: "This policy setting determines the least number of characters that make up a password for a user account.".into(),
            rationale: "Types of password attacks include dictionary attacks and brute force attacks. Longer passwords make these attacks more difficult.".into(),
        }),
        ("2.3.11.1", CisControlInfo {
            title: "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'".into(),
            level: CisLevel::Level1,
            description: "LAN Manager (LM) is an older Microsoft authentication protocol that was replaced by NTLMv2.".into(),
            rationale: "NTLMv2 is more secure than LM and NTLM due to improved cryptographic protections.".into(),
        }),
    ];

    controls.into_iter()
        .find(|(id, _)| *id == control_id)
        .map(|(_, info)| info)
}

#[derive(Debug, Clone)]
pub struct CisControlInfo {
    pub title: String,
    pub level: CisLevel,
    pub description: String,
    pub rationale: String,
}

/// Audit a tenant's configuration against CIS benchmarks
pub fn audit_against_cis(current_config: &Value, level: CisLevel) -> CisAuditResult {
    let baseline = match level {
        CisLevel::Level1 => generate_cis_level1("Audit"),
        CisLevel::Level2 => generate_cis_level2("Audit"),
        CisLevel::BitLocker => {
            let mut policies = generate_cis_level2("Audit");
            policies.extend(generate_cis_bitlocker("Audit"));
            policies
        }
    };

    // Count total expected settings
    let total_controls = baseline.len() * 5; // Approximate settings per policy
    let mut compliant_count = 0;
    let mut findings: Vec<CisFinding> = Vec::new();

    // Check current config against baseline
    // This is a simplified audit - in production would do deep comparison

    for policy in &baseline {
        if let Some(policy_name) = policy["displayName"].as_str() {
            // Check if equivalent policy exists in current config
            let exists = current_config["policies"]
                .as_array()
                .map(|arr| arr.iter().any(|p| {
                    p["displayName"].as_str()
                        .map(|n| n.contains(&policy_name.replace(" - CIS L1 ", " - ").replace(" - CIS L2 ", " - ")))
                        .unwrap_or(false)
                }))
                .unwrap_or(false);

            if exists {
                compliant_count += 5;
            } else {
                findings.push(CisFinding {
                    control: policy_name.to_string(),
                    severity: match level {
                        CisLevel::Level1 => "High".to_string(),
                        CisLevel::Level2 => "Medium".to_string(),
                        CisLevel::BitLocker => "High".to_string(),
                    },
                    status: "Missing".to_string(),
                    recommendation: format!("Deploy {} policy", policy_name),
                });
            }
        }
    }

    let compliance_score = if total_controls > 0 {
        (compliant_count as f32 / total_controls as f32) * 100.0
    } else {
        0.0
    };

    CisAuditResult {
        level,
        total_controls: total_controls as u32,
        compliant: compliant_count as u32,
        non_compliant: (total_controls - compliant_count) as u32,
        compliance_score,
        findings,
    }
}

#[derive(Debug)]
pub struct CisAuditResult {
    pub level: CisLevel,
    pub total_controls: u32,
    pub compliant: u32,
    pub non_compliant: u32,
    pub compliance_score: f32,
    pub findings: Vec<CisFinding>,
}

#[derive(Debug)]
pub struct CisFinding {
    pub control: String,
    pub severity: String,
    pub status: String,
    pub recommendation: String,
}
