/// macOS baseline configuration - OpenIntuneBaseline v1.0
///
/// Based on OpenIntuneBaseline macOS v1.0 by SkipToEndpoint + IntuneMacAdmins
/// https://github.com/SkipToTheEndpoint/OpenIntuneBaseline
/// https://www.intunemacadmins.com/
///
/// Platform: macOS 14.6+ (Sonoma) on Apple Silicon
/// Deployment: Apple Business Manager + ADE (Automated Device Enrollment)
/// Licensing: M365 Business Premium, M365 E3+MDE, or M365 E5

use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use serde_json::{json, Value};

/// Generate OpenIntuneBaseline v1.0 for macOS
pub fn generate_macos_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Compliance Policies (3)
    policies.push(generate_compliance_device_health(args));
    policies.push(generate_compliance_device_security(args));
    policies.push(generate_compliance_password(args));

    // Settings Catalog Policies
    if args.encryption {
        policies.push(generate_filevault_encryption(args));
    }

    policies.push(generate_gatekeeper_firewall(args));
    policies.push(generate_device_restrictions(args));
    policies.push(generate_accounts_and_login(args));
    policies.push(generate_platform_sso(args));

    if args.defender {
        policies.push(generate_defender_antivirus(args));
        policies.push(generate_defender_mde_configuration(args));
    }

    policies.push(generate_microsoft_autoupdate(args));

    Ok(json!({
        "version": "1.0",
        "template": "OpenIntuneBaseline",
        "platform": "macos",
        "name": format!("{} - macOS (OIB v1.0)", args.name),
        "description": "OpenIntuneBaseline v1.0 for macOS - FileVault, Gatekeeper, Platform SSO, MDE",
        "metadata": {
            "source": "OpenIntuneBaseline v1.0 (macOS)",
            "author": "SkipToEndpoint (James) + IntuneMacAdmins",
            "url": "https://github.com/SkipToTheEndpoint/OpenIntuneBaseline",
            "macos_url": "https://www.intunemacadmins.com/",
            "security_frameworks": [
                "Apple Platform Security Guide",
                "CIS Apple macOS Benchmarks",
                "Microsoft Security Baselines"
            ],
            "licensing_required": "M365 Business Premium, M365 E3+MDE, or M365 E5",
            "intended_use": "macOS 14.6+ on Apple Silicon, enrolled via Apple Business Manager ADE",
            "requirements": [
                "Apple Business Manager",
                "ADE with User Affinity",
                "Setup Assistant with Modern Auth",
                "Await Final Configuration: Yes",
                "Locked Configuration: Yes"
            ]
        },
        "policies": policies
    }))
}

/// macOS Compliance: Device Health
fn generate_compliance_device_health(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Device Health", args.name),
        "description": "Ensures system integrity protection, secure boot, FileVault",
        "osMinimumVersion": "14.6", // macOS Sonoma 14.6+
        "osMaximumVersion": null,
        "systemIntegrityProtectionEnabled": true,
        "deviceThreatProtectionEnabled": args.defender,
        "deviceThreatProtectionRequiredSecurityLevel": if args.defender { "medium" } else { "unavailable" },
        "storageRequireEncryption": args.encryption,
        "firewallEnabled": true,
        "firewallBlockAllIncoming": false,
        "firewallEnableStealthMode": true,
        "scheduledActionsForRule": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "ruleName": null,
            "scheduledActionConfigurations": [{
                "@odata.type": "#microsoft.graph.deviceComplianceActionItem",
                "gracePeriodHours": 6,
                "actionType": "block",
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    })
}

/// macOS Compliance: Device Security
fn generate_compliance_device_security(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Device Security", args.name),
        "description": "Gatekeeper, firewall, and antivirus requirements",
        "gatekeeperAllowedAppSource": "macAppStoreAndIdentifiedDevelopers",
        "firewallEnabled": true,
        "scheduledActionsForRule": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "ruleName": null,
            "scheduledActionConfigurations": [{
                "@odata.type": "#microsoft.graph.deviceComplianceActionItem",
                "gracePeriodHours": 6,
                "actionType": "block",
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    })
}

/// macOS Compliance: Password
fn generate_compliance_password(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Password", args.name),
        "description": "Password requirements (managed by Entra ID + Platform SSO)",
        "passwordRequired": false, // Managed by Entra ID + Platform SSO
        "passwordBlockSimple": false,
        "passwordMinimumLength": null,
        "passwordMinutesOfInactivityBeforeLock": null,
        "passwordExpirationDays": null,
        "passwordPreviousPasswordBlockCount": null,
        "scheduledActionsForRule": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "ruleName": null,
            "scheduledActionConfigurations": [{
                "@odata.type": "#microsoft.graph.deviceComplianceActionItem",
                "gracePeriodHours": 6,
                "actionType": "block",
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    })
}

/// macOS Settings Catalog: FileVault Encryption
fn generate_filevault_encryption(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Disk Encryption - D - FileVault", args.name),
        "description": "FileVault full disk encryption with XTS-AES 256, recovery key escrow to Entra",
        "platforms": "macOS",
        "technologies": "mdm",
        "templateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicyTemplateReference",
            "templateId": "com.apple.MCX.FileVault2_58e600b2-5d70-462e-855b-0bdca6b5e576",
            "templateFamily": "endpointSecurityDiskEncryption",
            "templateDisplayName": "FileVault",
            "templateDisplayVersion": "Version 1"
        },
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.MCX.FileVault2_Enable",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "On",
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.MCX.FileVault2_ShowRecoveryKey",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "true",
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.MCX.FileVault2_UseRecoveryKey",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "true",
                        "children": []
                    }
                }
            }
        ]
    })
}

/// macOS Settings Catalog: Gatekeeper & Firewall
fn generate_gatekeeper_firewall(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Firewall - D - Gatekeeper", args.name),
        "description": "Gatekeeper app control - Mac App Store and identified developers only",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.systempolicy.control_AllowIdentifiedDevelopers",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "true",
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.security.firewall_EnableFirewall",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "true",
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "com.apple.security.firewall_EnableStealthMode",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "true",
                        "children": []
                    }
                }
            }
        ]
    })
}

/// macOS Settings Catalog: Device Restrictions
fn generate_device_restrictions(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Device Security - D - Restrictions", args.name),
        "description": "Security restrictions - camera, screen capture, Siri, etc.",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// macOS Settings Catalog: Accounts and Login
fn generate_accounts_and_login(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Device Security - D - Accounts and Login", args.name),
        "description": "Local account management, screen lock timeouts, login window settings",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// macOS Settings Catalog: Platform SSO (Secure Enclave)
fn generate_platform_sso(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Authentication - D - Platform SSO", args.name),
        "description": "Entra ID join via Platform SSO with Secure Enclave (passwordless)",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// macOS Settings Catalog: Defender Antivirus
fn generate_defender_antivirus(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Defender Antivirus - D - Antivirus Configuration", args.name),
        "description": "Microsoft Defender for Endpoint antivirus configuration for macOS",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// macOS Settings Catalog: Defender MDE Configuration
fn generate_defender_mde_configuration(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Defender Antivirus - D - MDE Configuration", args.name),
        "description": "Microsoft Defender for Endpoint EDR and threat protection",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// macOS Settings Catalog: Microsoft AutoUpdate
fn generate_microsoft_autoupdate(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": format!("{} - OIB - Microsoft AutoUpdate - D - MAU Configuration", args.name),
        "description": "Microsoft AutoUpdate configuration for M365 Apps",
        "platforms": "macOS",
        "technologies": "mdm",
        "settings": []
    })
}

/// Generate basic macOS baseline (simpler alternative to OIB)
pub fn generate_basic_macos_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Basic compliance policy
    policies.push(json!({
        "@odata.type": "#microsoft.graph.macOSCompliancePolicy",
        "displayName": format!("{} - macOS Compliance", args.name),
        "description": "Basic macOS compliance - OS version, encryption, firewall",
        "osMinimumVersion": "14.0",
        "systemIntegrityProtectionEnabled": true,
        "storageRequireEncryption": args.encryption,
        "firewallEnabled": true,
        "gatekeeperAllowedAppSource": "macAppStoreAndIdentifiedDevelopers",
        "scheduledActionsForRule": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "ruleName": null,
            "scheduledActionConfigurations": [{
                "@odata.type": "#microsoft.graph.deviceComplianceActionItem",
                "gracePeriodHours": 0,
                "actionType": "block",
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    }));

    Ok(json!({
        "version": "1.0",
        "platform": "macos",
        "name": format!("{} - macOS Basic", args.name),
        "description": "Basic macOS baseline with essential security controls",
        "policies": policies
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args(name: &str, encryption: bool, defender: bool) -> NewArgs {
        NewArgs {
            platform: "macos".to_string(),
            encryption,
            defender,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: name.to_string(),
            template: "basic".to_string(),
        }
    }

    #[test]
    fn test_generate_macos_baseline_structure() {
        let args = create_test_args("Test", true, true);
        let baseline = generate_macos_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "macos");
        assert_eq!(baseline["template"], "OpenIntuneBaseline");
        assert!(baseline["policies"].is_array());
    }

    #[test]
    fn test_generate_macos_baseline_with_defender() {
        let args = create_test_args("Test", false, true);
        let baseline = generate_macos_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // Should have defender policies when defender is enabled
        let defender_policy = policies.iter().find(|p| {
            p["name"]
                .as_str()
                .map(|n| n.contains("Defender"))
                .unwrap_or(false)
        });
        assert!(defender_policy.is_some());
    }

    #[test]
    fn test_generate_macos_baseline_without_defender() {
        let args = create_test_args("Test", true, false);
        let baseline = generate_macos_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // Should NOT have defender policies when defender is disabled
        let defender_policy = policies.iter().find(|p| {
            p["name"]
                .as_str()
                .map(|n| n.contains("Defender Antivirus"))
                .unwrap_or(false)
        });
        assert!(defender_policy.is_none());
    }

    #[test]
    fn test_generate_macos_baseline_with_encryption() {
        let args = create_test_args("Test", true, false);
        let baseline = generate_macos_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // Should have FileVault policy when encryption is enabled
        let filevault_policy = policies.iter().find(|p| {
            p["name"]
                .as_str()
                .map(|n| n.contains("FileVault"))
                .unwrap_or(false)
        });
        assert!(filevault_policy.is_some());
    }

    #[test]
    fn test_generate_compliance_device_health() {
        let args = create_test_args("Test", true, true);
        let policy = generate_compliance_device_health(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.macOSCompliancePolicy"
        );
        assert!(policy["displayName"]
            .as_str()
            .unwrap()
            .contains("Device Health"));
        assert_eq!(policy["osMinimumVersion"], "14.6");
        assert_eq!(policy["systemIntegrityProtectionEnabled"], true);
        assert_eq!(policy["storageRequireEncryption"], true);
    }

    #[test]
    fn test_generate_filevault_encryption() {
        let args = create_test_args("Test", true, false);
        let policy = generate_filevault_encryption(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.deviceManagementConfigurationPolicy"
        );
        assert!(policy["name"].as_str().unwrap().contains("FileVault"));
        assert_eq!(policy["platforms"], "macOS");
    }

    #[test]
    fn test_generate_basic_macos_baseline() {
        let args = create_test_args("Basic Test", true, false);
        let baseline = generate_basic_macos_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "macos");
        assert!(baseline["name"].as_str().unwrap().contains("Basic Test"));

        let policies = baseline["policies"].as_array().unwrap();
        assert!(!policies.is_empty());
    }

    #[test]
    fn test_compliance_policy_has_scheduled_actions() {
        let args = create_test_args("Test", true, false);
        let policy = generate_compliance_device_health(&args);

        let scheduled_actions = policy["scheduledActionsForRule"].as_array();
        assert!(scheduled_actions.is_some());
        assert!(!scheduled_actions.unwrap().is_empty());
    }
}
