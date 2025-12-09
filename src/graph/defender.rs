//! Microsoft Defender for Business / Endpoint configuration
//!
//! Manages Defender ATP policies, onboarding, and threat protection

#![allow(dead_code)]

use crate::error::Result;
use crate::graph::GraphClient;
use serde_json::{Value, json};

/// Get Defender for Endpoint onboarding package
pub async fn get_onboarding_package(client: &GraphClient) -> Result<Value> {
    client
        .get("deviceManagement/advancedThreatProtectionOnboardingStateSummary")
        .await
}

/// Generate Defender ATP onboarding configuration policy
pub fn generate_atp_onboarding_policy(name: &str, onboarding_blob: &str) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": name,
        "description": "Onboard Windows devices to Microsoft Defender for Endpoint",
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingString",
                "displayName": "Defender ATP Onboarding Blob",
                "description": "Onboards device to Microsoft Defender for Endpoint",
                "omaUri": "./Device/Vendor/MSFT/WindowsAdvancedThreatProtection/Onboarding",
                "value": onboarding_blob
            }
        ]
    })
}

/// Generate Defender for Business recommended settings
pub fn generate_defender_for_business_baseline(name: &str) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": name,
        "description": "Microsoft Defender for Business recommended configuration",
        "platforms": "windows10",
        "technologies": "mdm",
        "templateReference": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicyTemplateReference",
            "templateId": "804339ad-1553-4478-a742-138fb5807418_1",
            "templateFamily": "endpointSecurityAntivirus",
            "templateDisplayName": "Microsoft Defender Antivirus",
            "templateDisplayVersion": "Version 1"
        },
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowcloudprotection",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "device_vendor_msft_policy_config_defender_allowcloudprotection_1", // Enabled
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_submitsamplesconsent",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "device_vendor_msft_policy_config_defender_submitsamplesconsent_3", // Send all samples automatically
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_puaprotection",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "device_vendor_msft_policy_config_defender_puaprotection_1", // Enabled
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowrealtimemonitoring",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1", // Allowed
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_cloudblocklevel",
                    "choiceSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                        "value": "device_vendor_msft_policy_config_defender_cloudblocklevel_2", // High
                        "children": []
                    }
                }
            },
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_cloudextendedtimeout",
                    "simpleSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                        "value": 50 // 50 second cloud check timeout
                    }
                }
            }
        ]
    })
}

/// Generate Attack Surface Reduction (ASR) rules for Defender for Business
pub fn generate_asr_rules_defender_for_business(name: &str, mode: &str) -> Value {
    // ASR rule mode: 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn
    let rule_mode = match mode {
        "block" => "1",
        "audit" => "2",
        "warn" => "6",
        _ => "1", // Default to block
    };

    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationPolicy",
        "name": name,
        "description": "Attack Surface Reduction rules - Defender for Business recommended",
        "platforms": "windows10",
        "technologies": "mdm",
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingInstance",
                    "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                    "groupSettingValue": {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingValue",
                        "children": [
                            // Block executable content from email and webmail
                            create_asr_rule("BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", rule_mode),
                            // Block Office apps from creating executable content
                            create_asr_rule("3B576869-A4EC-4529-8536-B80A7769E899", rule_mode),
                            // Block Office apps from injecting code into other processes
                            create_asr_rule("75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", rule_mode),
                            // Block JavaScript or VBScript from launching downloaded executable content
                            create_asr_rule("D3E037E1-3EB8-44C8-A917-57927947596D", rule_mode),
                            // Block execution of potentially obfuscated scripts
                            create_asr_rule("5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", rule_mode),
                            // Block Win32 API calls from Office macros
                            create_asr_rule("92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", rule_mode),
                            // Block credential stealing from LSASS
                            create_asr_rule("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", rule_mode),
                            // Block untrusted and unsigned processes from USB
                            create_asr_rule("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", rule_mode),
                            // Block Adobe Reader from creating child processes
                            create_asr_rule("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", rule_mode),
                            // Block persistence through WMI event subscription
                            create_asr_rule("e6db77e5-3df2-4cf1-b95a-636979351e5b", rule_mode),
                        ]
                    }
                }
            }
        ]
    })
}

fn create_asr_rule(rule_id: &str, mode: &str) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId": format!("device_vendor_msft_policy_config_defender_attacksurfacereductionrules_{}", rule_id.to_lowercase()),
        "choiceSettingValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "value": mode,
            "children": []
        }
    })
}

/// Get Defender for Endpoint device compliance status
pub async fn get_device_compliance_status(client: &GraphClient) -> Result<Value> {
    client
        .get("deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$select=id,deviceName,complianceState,lastSyncDateTime")
        .await
}

/// Get Defender threat detections
pub async fn get_threat_detections(client: &GraphClient) -> Result<Value> {
    client
        .get("security/alerts_v2?$filter=classification eq 'malware' or classification eq 'ransomware'")
        .await
}

/// Enable Defender for Endpoint connector (links Intune with Microsoft 365 Defender portal)
pub async fn enable_defender_connector(client: &GraphClient) -> Result<Value> {
    let payload = json!({
        "@odata.type": "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration",
        "allowSampleSharing": true,
        "enableExpeditedTelemetryReporting": true
    });

    client
        .post(
            "deviceManagement/advancedThreatProtectionOnboardingStateSummary",
            &payload,
        )
        .await
}

/// Get Defender connector status
pub async fn get_defender_connector_status(client: &GraphClient) -> Result<Value> {
    client
        .get("deviceManagement/advancedThreatProtectionOnboardingStateSummary")
        .await
}

/// Configure Defender for Business automatic onboarding for Intune devices
pub async fn configure_automatic_onboarding(client: &GraphClient, enable: bool) -> Result<Value> {
    let payload = json!({
        "@odata.type": "#microsoft.graph.windowsDefenderAdvancedThreatProtectionConfiguration",
        "advancedThreatProtectionAutoPopulateOnboardingBlob": enable,
        "advancedThreatProtectionOffboardingFilename": "",
        "advancedThreatProtectionOffboardingBlob": ""
    });

    client
        .patch(
            "deviceManagement/advancedThreatProtectionOnboardingStateSummary",
            &payload,
        )
        .await
}
