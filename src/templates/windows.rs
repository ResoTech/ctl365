use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use serde_json::{Value, json};
use std::fs;

/// Generate a complete Windows 11 baseline configuration
pub fn generate_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // 1. Compliance Policy
    policies.push(generate_compliance_policy(args));

    // 2. Endpoint Protection (Defender + Firewall)
    policies.push(generate_endpoint_protection(args));

    // 3. BitLocker Configuration (if enabled)
    if args.encryption {
        policies.push(generate_bitlocker_policy(args));
    }

    // 4. Microsoft Defender for Endpoint Onboarding (if provided)
    if args.mde_onboarding.is_some() {
        policies.push(generate_mde_onboarding(args)?);
    }

    Ok(json!({
        "version": "1.0",
        "platform": "windows",
        "name": format!("{} - Windows 11", args.name),
        "description": "Enterprise baseline for Windows 11 with BitLocker, Defender, and compliance",
        "policies": policies
    }))
}

/// Generate Windows 10/11 Compliance Policy
fn generate_compliance_policy(args: &NewArgs) -> Value {
    let min_os = args.min_os.as_deref().unwrap_or("10.0.26100.0"); // Windows 11 25H2 default

    json!({
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": format!("{} - Windows Compliance", args.name),
        "description": "Baseline Windows compliance – BitLocker, Defender, minimum OS",
        "passwordRequired": true,
        "passwordMinimumLength": 6,
        "osMinimumVersion": min_os,
        "bitLockerEnabled": args.encryption,
        "deviceThreatProtectionEnabled": args.defender,
        "deviceThreatProtectionRequiredSecurityLevel": "secured",
        "activeFirewallRequired": true,
        "defenderEnabled": true,
        "secureBootEnabled": true,
        "codeIntegrityEnabled": true,
        "earlyLaunchAntiMalwareDriverEnabled": true,
        "scheduledActionsForRule": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "ruleName": "PasswordRequired",
            "scheduledActionConfigurations": [{
                "@odata.type": "#microsoft.graph.deviceComplianceActionItem",
                "gracePeriodHours": 0,
                "actionType": "block",
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    })
}

/// Generate Endpoint Protection Configuration (Defender + Firewall + SmartScreen)
fn generate_endpoint_protection(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
        "displayName": format!("{} - Endpoint Protection", args.name),
        "description": "Managed Defender, Firewall, SmartScreen protection",

        // Windows Defender Antivirus
        "defenderBlockOnPotentiallyUnwantedApps": "enable",
        "defenderCloudBlockLevel": "high",
        "defenderCloudExtendedTimeout": 50,
        "defenderCloudExtendedTimeoutInSeconds": 50,
        "defenderDaysBeforeDeletingQuarantinedMalware": 30,
        "defenderDetectedMalwareActions": {
            "lowSeverity": "quarantine",
            "moderateSeverity": "quarantine",
            "highSeverity": "quarantine",
            "severeSeverity": "quarantine"
        },
        "defenderFileExtensionsToExclude": [],
        "defenderFilesAndFoldersToExclude": [],
        "defenderProcessesToExclude": [],

        // Cloud Protection
        "defenderCloudProtection": "enable",
        "defenderAutomaticSampleSubmission": "enable",
        "defenderSubmitSamplesConsentType": "sendAllSamplesAutomatically",

        // Scanning
        "defenderScanArchiveFiles": true,
        "defenderScanDownloads": true,
        "defenderScanIncomingMail": true,
        "defenderScanMappedNetworkDrivesDuringFullScan": true,
        "defenderScanNetworkFiles": true,
        "defenderScanRemovableDrivesDuringFullScan": true,
        "defenderScanScriptsLoadedInInternetExplorer": true,
        "defenderScanType": "quick",
        "defenderScheduledScanTime": "02:00:00.0000000",
        "defenderScheduledQuickScanTime": "06:00:00.0000000",
        "defenderSignatureUpdateIntervalInHours": 4,

        // Real-time Protection
        "defenderRealTimeScanDirection": "monitorAllFiles",
        "defenderMonitorFileActivity": "monitorAllFiles",
        "defenderPotentiallyUnwantedAppAction": "block",
        "defenderPotentiallyUnwantedAppActionSetting": "enable",

        // System Guard
        "defenderSecurityCenterDisableAppBrowserUI": false,
        "defenderSecurityCenterDisableFamilyUI": false,
        "defenderSecurityCenterDisableHealthUI": false,
        "defenderSecurityCenterDisableNetworkUI": false,
        "defenderSecurityCenterDisableVirusUI": false,
        "defenderSecurityCenterDisableAccountUI": false,
        "defenderSecurityCenterDisableClearTpmUI": false,
        "defenderSecurityCenterDisableHardwareUI": false,
        "defenderSecurityCenterDisableNotificationAreaUI": false,
        "defenderSecurityCenterDisableRansomwareUI": false,
        "defenderSecurityCenterDisableSecureBootUI": false,
        "defenderSecurityCenterDisableTroubleshootingUI": false,
        "defenderSecurityCenterOrganizationDisplayName": "",
        "defenderSecurityCenterHelpEmail": "",
        "defenderSecurityCenterHelpPhone": "",
        "defenderSecurityCenterHelpURL": "",
        "defenderSecurityCenterNotificationsFromApp": "blockNoncriticalNotifications",
        "defenderSecurityCenterITContactDisplay": "notConfigured",

        // Firewall - Domain Profile
        "firewallProfileDomain": {
            "firewallEnabled": "allowed",
            "stealthModeBlocked": false,
            "incomingTrafficBlocked": true,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "inboundNotificationsBlocked": false,
            "authorizedApplicationRulesFromGroupPolicyMerged": true,
            "globalPortRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyMerged": true,
            "outboundConnectionsBlocked": false,
            "inboundConnectionsBlocked": true,
            "securedPacketExemptionAllowed": true,
            "policyRulesFromGroupPolicyMerged": true
        },

        // Firewall - Private Profile
        "firewallProfilePrivate": {
            "firewallEnabled": "allowed",
            "stealthModeBlocked": false,
            "incomingTrafficBlocked": true,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "inboundNotificationsBlocked": false,
            "authorizedApplicationRulesFromGroupPolicyMerged": true,
            "globalPortRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyMerged": true,
            "outboundConnectionsBlocked": false,
            "inboundConnectionsBlocked": true,
            "securedPacketExemptionAllowed": true,
            "policyRulesFromGroupPolicyMerged": true
        },

        // Firewall - Public Profile
        "firewallProfilePublic": {
            "firewallEnabled": "allowed",
            "stealthModeBlocked": false,
            "incomingTrafficBlocked": true,
            "unicastResponsesToMulticastBroadcastsBlocked": true,
            "inboundNotificationsBlocked": false,
            "authorizedApplicationRulesFromGroupPolicyMerged": true,
            "globalPortRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyMerged": true,
            "outboundConnectionsBlocked": false,
            "inboundConnectionsBlocked": true,
            "securedPacketExemptionAllowed": true,
            "policyRulesFromGroupPolicyMerged": true,
            "connectionSecurityRulesFromGroupPolicyNotMerged": false
        },

        // SmartScreen
        "smartScreenEnableInShell": true,
        "smartScreenBlockOverrideForFiles": true,

        // Application Guard
        "applicationGuardEnabled": false,
        "applicationGuardEnabledOptions": "notConfigured",
        "applicationGuardBlockFileTransfer": "notConfigured",
        "applicationGuardBlockNonEnterpriseContent": false,
        "applicationGuardAllowPersistence": false,
        "applicationGuardForceAuditing": false,
        "applicationGuardBlockClipboardSharing": "notConfigured",
        "applicationGuardAllowPrintToPDF": false,
        "applicationGuardAllowPrintToXPS": false,
        "applicationGuardAllowPrintToLocalPrinters": false,
        "applicationGuardAllowPrintToNetworkPrinters": false,
        "applicationGuardAllowVirtualGPU": false,
        "applicationGuardAllowFileSaveOnHost": false,

        // BitLocker (basic enforcement - detailed config in separate policy)
        "bitLockerSystemDrivePolicy": null,
        "bitLockerFixedDrivePolicy": null,
        "bitLockerRemovableDrivePolicy": null,
        "bitLockerRecoveryPasswordRotation": "notConfigured"
    })
}

/// Generate BitLocker Drive Encryption Policy
fn generate_bitlocker_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
        "displayName": format!("{} - BitLocker", args.name),
        "description": "BitLocker OS drive encryption enforcement with recovery key escrow",

        // BitLocker - System Drive (OS Drive)
        "bitLockerSystemDrivePolicy": {
            "encryptionMethod": "xtsAes256",
            "startupAuthenticationRequired": true,
            "startupAuthenticationBlockWithoutTpmChip": false,
            "startupAuthenticationTpmUsage": "required",
            "startupAuthenticationTpmPinUsage": "blocked",
            "startupAuthenticationTpmKeyUsage": "blocked",
            "startupAuthenticationTpmPinAndKeyUsage": "blocked",
            "minimumPinLength": 6,
            "recoveryOptions": {
                "blockDataRecoveryAgent": false,
                "recoveryPasswordUsage": "allowed",
                "recoveryKeyUsage": "allowed",
                "hideRecoveryOptions": false,
                "enableRecoveryInformationSaveToStore": true,
                "recoveryInformationToStore": "passwordAndKey",
                "enableBitLockerAfterRecoveryInformationToStore": true
            },
            "prebootRecoveryEnableMessageAndUrl": false,
            "prebootRecoveryMessage": "",
            "prebootRecoveryUrl": ""
        },

        // BitLocker - Fixed Drives
        "bitLockerFixedDrivePolicy": {
            "encryptionMethod": "xtsAes256",
            "requireEncryptionForWriteAccess": true,
            "recoveryOptions": {
                "blockDataRecoveryAgent": false,
                "recoveryPasswordUsage": "allowed",
                "recoveryKeyUsage": "allowed",
                "hideRecoveryOptions": false,
                "enableRecoveryInformationSaveToStore": true,
                "recoveryInformationToStore": "passwordAndKey",
                "enableBitLockerAfterRecoveryInformationToStore": true
            }
        },

        // BitLocker - Removable Drives
        "bitLockerRemovableDrivePolicy": {
            "encryptionMethod": "xtsAes256",
            "requireEncryptionForWriteAccess": false,
            "blockCrossOrganizationWriteAccess": false
        },

        // Recovery Key Rotation
        "bitLockerRecoveryPasswordRotation": "enabledForAzureAd",

        // Store recovery keys in Azure AD
        "bitLockerDisableWarningForOtherDiskEncryption": false,
        "bitLockerEnableStorageCardEncryptionOnMobile": false,
        "bitLockerEncryptDevice": true,
        "bitLockerAllowStandardUserEncryption": true
    })
}

/// Generate Microsoft Defender for Endpoint Onboarding Configuration
fn generate_mde_onboarding(args: &NewArgs) -> Result<Value> {
    let mde_path = args.mde_onboarding.as_ref().ok_or_else(|| {
        crate::error::Error::ConfigError("MDE onboarding path not provided".into())
    })?;

    // Read the MDE onboarding XML file
    let mde_xml = fs::read_to_string(mde_path).map_err(|e| {
        crate::error::Error::ConfigError(format!("Failed to read MDE onboarding file: {}", e))
    })?;

    // Validate it's not empty
    if mde_xml.trim().is_empty() {
        return Err(crate::error::Error::ConfigError(
            "MDE onboarding file is empty".into(),
        ));
    }

    Ok(json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": format!("{} - Defender for Endpoint", args.name),
        "description": "Onboard Windows devices to Microsoft Defender for Endpoint",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "Defender for Endpoint Onboarding Blob",
                "description": "Onboards the device to Microsoft Defender for Endpoint",
                "omaUri": "./Device/Vendor/MSFT/WindowsAdvancedThreatProtection/Onboarding",
                "value": mde_xml
            }
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_compliance_policy() {
        let args = NewArgs {
            platform: "windows".to_string(),
            encryption: true,
            defender: true,
            min_os: Some("10.0.26100.0".to_string()),
            mde_onboarding: None,
            output: None,
            name: "Test".to_string(),
            template: "basic".to_string(),
            autopilot_group_name: None,
            bitlocker_policy_name: None,
            update_ring_name: None,
            feature_update_version: None,
            no_bitlocker: false,
            no_updates: false,
            firewall_policy_name: None,
            no_firewall: false,
        };

        let policy = generate_compliance_policy(&args);
        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.windows10CompliancePolicy"
        );
        assert_eq!(policy["bitLockerEnabled"], true);
        assert_eq!(policy["deviceThreatProtectionEnabled"], true);
        assert_eq!(policy["osMinimumVersion"], "10.0.26100.0");
    }

    #[test]
    fn test_generate_baseline_structure() {
        let args = NewArgs {
            platform: "windows".to_string(),
            encryption: true,
            defender: false,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: "Test Baseline".to_string(),
            template: "basic".to_string(),
            autopilot_group_name: None,
            bitlocker_policy_name: None,
            update_ring_name: None,
            feature_update_version: None,
            no_bitlocker: false,
            no_updates: false,
            firewall_policy_name: None,
            no_firewall: false,
        };

        let baseline = generate_baseline(&args).unwrap();
        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "windows");

        let policies = baseline["policies"].as_array().unwrap();
        // Should have: compliance + endpoint protection + bitlocker
        assert_eq!(policies.len(), 3);
    }
}
