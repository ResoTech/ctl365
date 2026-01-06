/// Windows Autopilot Baseline Configuration
///
/// Comprehensive Autopilot deployment baseline including:
/// - Dynamic security group for Autopilot devices
/// - User-driven Autopilot deployment profile (Entra joined)
/// - BitLocker disk encryption (Endpoint Security)
/// - Windows Update Ring and Feature Update policies
use crate::templates::settings_catalog::*;
use serde_json::{Value, json};

/// Configuration options for Windows Autopilot baseline
#[derive(Debug, Clone)]
pub struct AutopilotBaselineConfig {
    /// Display name prefix for all policies
    pub name_prefix: String,
    /// Name for the dynamic security group (default: "Windows Autopilot")
    pub group_name: String,
    /// BitLocker policy name (default: "{prefix} BitLocker")
    pub bitlocker_policy_name: Option<String>,
    /// Firewall policy name (default: "{prefix} Defender Firewall")
    pub firewall_policy_name: Option<String>,
    /// Update ring name (default: "Ring1")
    pub update_ring_name: String,
    /// Feature update version (default: "25H2")
    pub feature_update_version: String,
    /// Include BitLocker policy
    pub include_bitlocker: bool,
    /// Include Firewall policy
    pub include_firewall: bool,
    /// Include Windows Update policies
    pub include_updates: bool,
}

impl Default for AutopilotBaselineConfig {
    fn default() -> Self {
        Self {
            name_prefix: "Baseline".to_string(),
            group_name: "Windows Autopilot".to_string(),
            bitlocker_policy_name: None,
            firewall_policy_name: None,
            update_ring_name: "Ring1".to_string(),
            feature_update_version: "Windows 11, version 24H2".to_string(),
            include_bitlocker: true,
            include_firewall: true,
            include_updates: true,
        }
    }
}

/// Generate complete Windows Autopilot baseline
pub fn generate_autopilot_baseline(config: &AutopilotBaselineConfig) -> Value {
    let mut policies = Vec::new();

    // 1. Dynamic Security Group for Autopilot devices
    policies.push(generate_autopilot_security_group(config));

    // 2. Windows Autopilot Deployment Profile (User-driven, Entra joined)
    policies.push(generate_autopilot_deployment_profile(config));

    // 3. BitLocker Disk Encryption Policy (Endpoint Security)
    if config.include_bitlocker {
        policies.push(generate_bitlocker_disk_encryption(config));
    }

    // 4. Windows Defender Firewall Policy
    if config.include_firewall {
        policies.push(generate_defender_firewall(config));
    }

    // 5. Windows Update policies
    if config.include_updates {
        policies.push(generate_update_ring(config));
        policies.push(generate_feature_update_profile(config));
    }

    json!({
        "version": "1.0",
        "template": "windows-autopilot",
        "platform": "windows",
        "metadata": {
            "description": "Windows Autopilot baseline with BitLocker, Firewall, and Windows Updates",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &config.name_prefix
        },
        "policies": policies
    })
}

/// Generate dynamic security group for Windows Autopilot devices
///
/// Rule: (device.deviceOSType -eq "Windows") and
///       (device.deviceOSVersion -startsWith "10.0.2") and
///       (device.deviceOwnership -eq "Company")
fn generate_autopilot_security_group(config: &AutopilotBaselineConfig) -> Value {
    // Dynamic membership rule for Windows company-owned devices
    // deviceOSVersion starts with "10.0.2" covers Windows 11 (10.0.22000+, 10.0.26100+)
    let membership_rule = r#"(device.deviceOSType -eq "Windows") and (device.deviceOSVersion -startsWith "10.0.2") and (device.deviceOwnership -eq "Company")"#;

    json!({
        "@odata.type": "#microsoft.graph.group",
        "displayName": &config.group_name,
        "description": "Dynamic device group for Windows Autopilot - Company-owned Windows 11 devices",
        "mailEnabled": false,
        "mailNickname": config.group_name.to_lowercase().replace(' ', "-"),
        "securityEnabled": true,
        "groupTypes": ["DynamicMembership"],
        "membershipRule": membership_rule,
        "membershipRuleProcessingState": "On",
        "_ctl365_type": "securityGroup",
        "_ctl365_endpoint": "groups"
    })
}

/// Generate Windows Autopilot Deployment Profile
///
/// User-driven mode, Microsoft Entra joined (not hybrid)
fn generate_autopilot_deployment_profile(config: &AutopilotBaselineConfig) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
        "displayName": format!("{} - Autopilot User-Driven", config.name_prefix),
        "description": "User-driven Autopilot deployment profile for Microsoft Entra joined devices",

        // Deployment mode: User-driven
        "deploymentMode": "userDriven",

        // Microsoft Entra joined (NOT hybrid)
        "deviceType": "windowsPc",
        "extractHardwareHash": true,
        "deviceNameTemplate": "%SERIAL%",

        // Language and locale
        "language": "en-US",
        "locale": "en-US",

        // Disable white glove (pre-provisioning) by default
        "enableWhiteGlove": false,

        // Management settings
        "managementServiceAppId": "00000000-0000-0000-0000-000000000000",
        "hybridAzureADJoined": false,

        // Out of Box Experience (OOBE) settings
        "outOfBoxExperienceSettings": {
            "hidePrivacySettings": true,
            "hideEULA": true,
            "userType": "standard",
            "deviceUsageType": "singleUser",
            "skipKeyboardSelectionPage": true,
            "hideEscapeLink": true
        },

        "_ctl365_type": "autopilotProfile",
        "_ctl365_endpoint": "deviceManagement/windowsAutopilotDeploymentProfiles",
        "_ctl365_assign_to_group": &config.group_name
    })
}

/// Generate BitLocker Disk Encryption Policy (Endpoint Security)
///
/// Full encryption on OS drive, managed by Intune
/// Uses validated Settings Catalog IDs from OIB template
fn generate_bitlocker_disk_encryption(config: &AutopilotBaselineConfig) -> Value {
    let policy_name = config
        .bitlocker_policy_name
        .clone()
        .unwrap_or_else(|| format!("{} BitLocker", config.name_prefix));

    let policy = SettingsCatalogPolicy {
        name: policy_name,
        description: "BitLocker full disk encryption with TPM, XTS-AES 256, key escrow to Entra"
            .to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None, // Custom settings catalog policy
        settings: vec![
            // System drive encryption type: Full encryption
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_systemdrivesencryptiontype",
                "device_vendor_msft_bitlocker_systemdrivesencryptiontype_1",
                vec![choice_setting(
                    "device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name",
                    "device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1",
                )],
            ),
            // Require startup authentication - TPM only (no PIN required)
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication",
                "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1",
                vec![
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name_0",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name_0",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name_0",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name_0",
                    ),
                ],
            ),
            // Recovery options - enable key escrow to Entra ID
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions",
                "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_1",
                vec![
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_oshiderecoverypage_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_oshiderecoverypage_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osallowdra_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osallowdra_name_0",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackupdropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackupdropdown_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrequireactivedirectorybackup_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackup_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osactivedirectorybackup_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverypasswordusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverypasswordusagedropdown_name_1",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverykeyusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrecoveryoptions_osrecoverykeyusagedropdown_name_0",
                    ),
                ],
            ),
            // Encryption algorithm: XTS-AES 256
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_encryptionmethodbydrivetype",
                "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_1",
                vec![
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name_4",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name_7",
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name_7",
                    ),
                ],
            ),
        ],
    };

    let mut json_policy = policy.to_json();
    // Add ctl365 metadata for assignment
    json_policy["_ctl365_type"] = json!("endpointSecurityPolicy");
    json_policy["_ctl365_endpoint"] = json!("deviceManagement/configurationPolicies");
    json_policy["_ctl365_assign_to_group"] = json!(&config.group_name);
    json_policy
}

/// Generate Windows Defender Firewall Policy
///
/// Enables firewall for all network profiles with:
/// - Domain, Private, Public network firewalls enabled
/// - Default inbound: Block
/// - Default outbound: Allow
fn generate_defender_firewall(config: &AutopilotBaselineConfig) -> Value {
    let policy_name = config
        .firewall_policy_name
        .clone()
        .unwrap_or_else(|| format!("{} Defender Firewall", config.name_prefix));

    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": policy_name,
        "description": "Windows Defender Firewall - Domain, Private, and Public network profiles enabled with default inbound block",
        "platforms": "windows10",
        "technologies": "mdm,microsoftSense",
        "templateReference": {
            "templateFamily": "endpointSecurityFirewall",
            "templateDisplayName": "Windows Firewall",
            "templateDisplayVersion": "Version 1"
        },
        "settings": [
            // ==========================================
            // Domain Network Firewall
            // ==========================================
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall_true",
                        "children": []
                    }
                }
            },
            // Domain - Default Inbound Action: Block
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_defaultinboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_domainprofile_defaultinboundaction_1",
                        "children": []
                    }
                }
            },
            // Domain - Default Outbound Action: Allow
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_defaultoutboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_domainprofile_defaultoutboundaction_0",
                        "children": []
                    }
                }
            },

            // ==========================================
            // Private Network Firewall
            // ==========================================
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall_true",
                        "children": []
                    }
                }
            },
            // Private - Default Inbound Action: Block
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_defaultinboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_privateprofile_defaultinboundaction_1",
                        "children": []
                    }
                }
            },
            // Private - Default Outbound Action: Allow
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_defaultoutboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_privateprofile_defaultoutboundaction_0",
                        "children": []
                    }
                }
            },

            // ==========================================
            // Public Network Firewall
            // ==========================================
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall_true",
                        "children": []
                    }
                }
            },
            // Public - Default Inbound Action: Block
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_defaultinboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_publicprofile_defaultinboundaction_1",
                        "children": []
                    }
                }
            },
            // Public - Default Outbound Action: Allow
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_defaultoutboundaction",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "vendor_msft_firewall_mdmstore_publicprofile_defaultoutboundaction_0",
                        "children": []
                    }
                }
            }
        ],
        "_ctl365_type": "endpointSecurityPolicy",
        "_ctl365_endpoint": "deviceManagement/configurationPolicies",
        "_ctl365_assign_to_group": &config.group_name
    })
}

/// Generate Windows Update Ring configuration
///
/// Configured per user specifications:
/// - Microsoft product updates: Allow
/// - Windows drivers: Allow
/// - Quality update deferral: 0 days
/// - Feature update deferral: 0 days
/// - Upgrade Win10 to Win11: Yes
/// - Auto install at maintenance time
/// - Active hours: 8 AM - 5 PM
/// - Deadlines: Feature 10 days, Quality 7 days, Grace 7 days
fn generate_update_ring(config: &AutopilotBaselineConfig) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration",
        "displayName": format!("{} - {}", config.name_prefix, config.update_ring_name),
        "description": "Windows Update ring - Auto install at maintenance time with deadlines",

        // Update settings
        "microsoftUpdateServiceAllowed": true,  // Microsoft product updates: Allow
        "driversExcluded": false,               // Windows drivers: Allow
        "qualityUpdatesDeferralPeriodInDays": 0,
        "featureUpdatesDeferralPeriodInDays": 0,
        "businessReadyUpdatesOnly": "all",      // Servicing channel: General Availability

        // Upgrade Windows 10 to Latest Windows 11 release
        "allowWindows11Upgrade": true,

        // Feature update uninstall period (2-60 days)
        "featureUpdatesRollbackWindowInDays": 10,

        // User experience settings
        "automaticUpdateMode": "autoInstallAtMaintenanceTime",
        "activeHoursStart": "08:00:00.0000000",
        "activeHoursEnd": "17:00:00.0000000",

        // Pause updates options
        "qualityUpdatesPaused": false,
        "featureUpdatesPaused": false,
        "userPauseAccess": "disabled",          // Option to pause: Disable
        "userWindowsUpdateScanAccess": "enabled", // Option to check for updates: Enable

        // Notification level: Default Windows Update notifications
        "updateNotificationLevel": "defaultNotifications",

        // Deadline settings
        "deadlineForFeatureUpdatesInDays": 10,
        "deadlineForQualityUpdatesInDays": 7,
        "deadlineGracePeriodInDays": 7,
        "postponeRebootUntilAfterDeadline": false, // Auto reboot before deadline: Yes (false = allow reboot)

        // Additional settings
        "installFeatureUpdatesOptional": false,
        "skipChecksBeforeRestart": false,
        "engagedRestartDeadlineInDays": null,
        "engagedRestartSnoozeScheduleInDays": null,
        "engagedRestartTransitionScheduleInDays": null,

        // Schedule install day and time
        "scheduleImminentRestartWarningInMinutes": 15,
        "scheduleRestartWarningInHours": 4,
        "autoRestartNotificationDismissal": "notConfigured",

        "_ctl365_type": "updateRing",
        "_ctl365_endpoint": "deviceManagement/deviceConfigurations",
        "_ctl365_assign_to_all": true
    })
}

/// Generate Feature Update profile for Windows 11 25H2
fn generate_feature_update_profile(config: &AutopilotBaselineConfig) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windowsFeatureUpdateProfile",
        "displayName": format!("{} - Feature Update {}", config.name_prefix,
            config.feature_update_version.split(',').next_back().unwrap_or("25H2").trim()),
        "description": format!("Deploy {} to all eligible devices", config.feature_update_version),

        // Target version - Windows 11 25H2 (24H2 is the internal version name for 25H2)
        "featureUpdateVersion": &config.feature_update_version,

        // Rollout settings
        "rolloutSettings": {
            "@odata.type": "microsoft.graph.windowsUpdateRolloutSettings",
            "offerStartDateTimeInUTC": null,  // Start immediately
            "offerEndDateTimeInUTC": null,
            "offerIntervalInDays": null
        },

        "_ctl365_type": "featureUpdateProfile",
        "_ctl365_endpoint": "deviceManagement/windowsFeatureUpdateProfiles",
        "_ctl365_assign_to_all": true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_autopilot_baseline() {
        let config = AutopilotBaselineConfig::default();
        let baseline = generate_autopilot_baseline(&config);

        assert_eq!(baseline["template"], "windows-autopilot");
        assert_eq!(baseline["platform"], "windows");

        let policies = baseline["policies"].as_array().unwrap();
        // Should have: group + autopilot profile + bitlocker + firewall + update ring + feature update
        assert_eq!(policies.len(), 6);
    }

    #[test]
    fn test_security_group_membership_rule() {
        let config = AutopilotBaselineConfig::default();
        let baseline = generate_autopilot_baseline(&config);
        let policies = baseline["policies"].as_array().unwrap();

        let group = &policies[0];
        let rule = group["membershipRule"].as_str().unwrap();

        assert!(rule.contains("device.deviceOSType -eq \"Windows\""));
        assert!(rule.contains("device.deviceOSVersion -startsWith \"10.0.2\""));
        assert!(rule.contains("device.deviceOwnership -eq \"Company\""));
    }

    #[test]
    fn test_autopilot_profile_is_user_driven() {
        let config = AutopilotBaselineConfig::default();
        let baseline = generate_autopilot_baseline(&config);
        let policies = baseline["policies"].as_array().unwrap();

        let profile = &policies[1];
        assert_eq!(profile["deploymentMode"], "userDriven");
        assert_eq!(
            profile["@odata.type"],
            "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile"
        );
    }

    #[test]
    fn test_custom_bitlocker_policy_name() {
        let config = AutopilotBaselineConfig {
            bitlocker_policy_name: Some("RESO BitLocker".to_string()),
            ..Default::default()
        };

        let baseline = generate_autopilot_baseline(&config);
        let policies = baseline["policies"].as_array().unwrap();

        let bitlocker = policies
            .iter()
            .find(|p| p["_ctl365_type"] == "endpointSecurityPolicy")
            .unwrap();

        assert_eq!(bitlocker["name"], "RESO BitLocker");
    }
}
