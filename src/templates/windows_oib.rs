/// OpenIntuneBaseline (OIB) Windows baseline implementation
///
/// Based on OpenIntuneBaseline v3.6 by SkipToEndpoint (James)
/// https://github.com/SkipToTheEndpoint/OpenIntuneBaseline
///
/// Security Framework Alignment:
/// - NCSC Device Security Guidance
/// - CIS Windows Benchmarks (with documented deviations)
/// - ACSC Essential Eight
/// - Microsoft Security Baselines
///
/// Platform: Windows 11 (compatible with Windows 10 Enterprise)
/// Licensing: M365 Business Premium, M365 E3+MDE, or M365 E5
use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use crate::templates::settings_catalog::*;
use serde_json::{Value, json};

use serde::{Deserialize, Serialize};

/// CIS Benchmark rationale for non-implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CISRationale {
    pub cis_ref: String,
    pub setting_name: String,
    pub rationale: String,
    pub notes: Option<String>,
}

/// Generate OpenIntuneBaseline v3.6 for Windows
pub fn generate_oib_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // OIB splits compliance into 4 separate policies for granularity
    policies.push(generate_compliance_defender_for_endpoint(args));
    policies.push(generate_compliance_device_health(args));
    policies.push(generate_compliance_device_security(args));
    policies.push(generate_compliance_password(args));

    // Settings Catalog Policies (Endpoint Security)
    if args.encryption {
        policies.push(generate_bitlocker_settings_catalog(args));
    }

    if args.defender {
        policies.push(generate_defender_antivirus_configuration(args));
        policies.push(generate_defender_security_experience(args));
        policies.push(generate_asr_rules_l2(args));
    }

    policies.push(generate_windows_firewall_configuration(args));

    // Windows Hello for Business (passwordless auth)
    policies.push(generate_windows_hello_for_business(args));

    // Windows LAPS (local admin password rotation)
    policies.push(generate_windows_laps_configuration(args));

    // Settings Catalog Policies (Security)
    policies.push(generate_device_security_login_and_lock_screen(args));
    policies.push(generate_credential_management_passwordless(args));
    policies.push(generate_device_security_power_and_device_lock(args));

    policies.push(generate_device_security_local_security_policies(args));
    policies.push(generate_device_security_hardening(args));

    // TODO Phase 3: Implement additional Device Security policies (User Rights, etc.)

    Ok(json!({
        "version": "3.6",
        "template": "OpenIntuneBaseline",
        "platform": "windows",
        "name": format!("{} - Windows (OIB v3.6)", args.name),
        "description": "OpenIntuneBaseline v3.6 - Production-tested Windows 11 25H2 baseline with CIS alignment",
        "metadata": {
            "source": "OpenIntuneBaseline v3.6",
            "author": "SkipToEndpoint (James)",
            "url": "https://github.com/SkipToTheEndpoint/OpenIntuneBaseline",
            "security_frameworks": [
                "NCSC Device Security Guidance",
                "CIS Windows Benchmarks (with deviations)",
                "ACSC Essential Eight",
                "Microsoft Security Baselines"
            ],
            "licensing_required": "M365 Business Premium, M365 E3+MDE, or M365 E5",
            "intended_use": "Entra joined, single-user Windows 11 devices via Autopilot"
        },
        "cis_deviations": get_cis_rationale(),
        "policies": policies
    }))
}

/// OIB Compliance: Defender for Endpoint
fn generate_compliance_defender_for_endpoint(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Defender for Endpoint", args.name),
        "description": "Ensures device is onboarded to Defender for Endpoint and at acceptable risk level",
        "deviceThreatProtectionEnabled": true,
        "deviceThreatProtectionRequiredSecurityLevel": "medium",
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

/// OIB Compliance: Device Health
fn generate_compliance_device_health(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Device Health", args.name),
        "description": "Ensures device attestation, secure boot, code integrity",
        "requireHealthyDeviceReport": true,
        "secureBootEnabled": true,
        "codeIntegrityEnabled": true,
        "memoryIntegrityEnabled": false, // Not enforced - hardware compatibility
        "kernelDmaProtectionEnabled": false, // Not enforced - hardware compatibility
        "virtualizationBasedSecurityEnabled": false, // Not enforced - hardware compatibility
        "firmwareProtectionEnabled": false, // Not enforced - hardware compatibility
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

/// OIB Compliance: Device Security
fn generate_compliance_device_security(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Device Security", args.name),
        "description": "TPM, firewall, antivirus requirements",
        "tpmRequired": true,
        "activeFirewallRequired": true,
        "antivirusRequired": true,
        "antiSpywareRequired": true,
        "defenderEnabled": false, // Monitored via MDE instead
        "rtpEnabled": false, // Monitored via MDE instead
        "signatureOutOfDate": false, // Monitored via MDE instead
        "bitLockerEnabled": false, // Separate encryption policy
        "storageRequireEncryption": false, // Separate encryption policy
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

/// OIB Compliance: Password
fn generate_compliance_password(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": format!("{} - OIB - Compliance - U - Password", args.name),
        "description": "Password/PIN requirements (managed by Entra ID + WHfB)",
        "passwordRequired": false, // Managed by Entra ID
        "passwordBlockSimple": false,
        "passwordRequiredToUnlockFromIdle": false,
        "passwordMinutesOfInactivityBeforeLock": null,
        "passwordExpirationDays": null, // Managed by Entra ID
        "passwordMinimumLength": null, // Managed by Entra ID
        "passwordMinimumCharacterSetCount": null,
        "passwordRequiredType": "deviceDefault",
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

/// OIB Settings Catalog: BitLocker (OS Disk)
fn generate_bitlocker_settings_catalog(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Encryption - D - BitLocker (OS Disk)", args.name),
        description: "BitLocker full disk encryption with TPM, XTS-AES 256, key escrow to Entra - Windows 11 25H2".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,  // Don't use template - create as custom settings catalog policy
        settings: vec![
            // System drive encryption type: Full encryption
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_systemdrivesencryptiontype",
                "device_vendor_msft_bitlocker_systemdrivesencryptiontype_1",
                vec![choice_setting(
                    "device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name",
                    "device_vendor_msft_bitlocker_systemdrivesencryptiontype_osencryptiontypedropdown_name_1", // Full encryption
                )],
            ),
            // Require startup authentication - TPM only (no PIN required)
            choice_setting_with_children(
                "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication",
                "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_1", // Enable
                vec![
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmpinkeyusagedropdown_name_0", // Blocked
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurepinusagedropdown_name_0", // Blocked
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmusagedropdown_name_1", // Allowed
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configurenontpmstartupkeyusage_name_0", // Blocked
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name",
                        "device_vendor_msft_bitlocker_systemdrivesrequirestartupauthentication_configuretpmstartupkeyusagedropdown_name_0", // Blocked
                    ),
                ],
            ),
            // Recovery options - enable key escrow to Entra ID (Azure AD)
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
                "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_1", // Configured
                vec![
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsrdvdropdown_name_4", // XTS-AES 128
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsfdvdropdown_name_7", // XTS-AES 256
                    ),
                    choice_setting(
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name",
                        "device_vendor_msft_bitlocker_encryptionmethodbydrivetype_encryptionmethodwithxtsosdropdown_name_7", // XTS-AES 256
                    ),
                ],
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Defender Antivirus Configuration
fn generate_defender_antivirus_configuration(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Defender Antivirus - D - AV Configuration", args.name),
        description: "Microsoft Defender Antivirus - cloud protection, real-time monitoring, scanning - Windows 11 25H2".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,  // Custom settings catalog policy
        settings: vec![
            // Cloud-delivered protection
            choice_setting("device_vendor_msft_policy_config_defender_allowcloudprotection", "device_vendor_msft_policy_config_defender_allowcloudprotection_1"),

            // Submit samples automatically
            choice_setting("device_vendor_msft_policy_config_defender_submitsamplesconsent", "device_vendor_msft_policy_config_defender_submitsamplesconsent_3"),

            // PUA protection
            choice_setting("device_vendor_msft_policy_config_defender_puaprotection", "device_vendor_msft_policy_config_defender_puaprotection_1"),

            // Real-time monitoring
            choice_setting("device_vendor_msft_policy_config_defender_allowrealtimemonitoring", "device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1"),

            // Scan archive files
            choice_setting("device_vendor_msft_policy_config_defender_allowarchivescanning", "device_vendor_msft_policy_config_defender_allowarchivescanning_1"),

            // Scan network files
            choice_setting("device_vendor_msft_policy_config_defender_allowscanningnetworkfiles", "device_vendor_msft_policy_config_defender_allowscanningnetworkfiles_1"),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Defender Security Experience
fn generate_defender_security_experience(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Defender Antivirus - D - Security Experience", args.name),
        description: "Windows Security app UI - Tamper Protection, notifications, family UI - Windows 11 25H2".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            // Tamper Protection (requires MDE P1/P2 or Defender for Business)
            choice_setting(
                "vendor_msft_defender_configuration_tamperprotection_options",
                "vendor_msft_defender_configuration_tamperprotection_options_0", // Disabled (requires MDE license)
            ),
            // Disable Family UI
            choice_setting(
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_disablefamilyui",
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_disablefamilyui_1", // Enabled
            ),
            // Enhanced notifications
            choice_setting(
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_disableenhancednotifications",
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_disableenhancednotifications_0", // Disabled
            ),
            // Show notification area control
            choice_setting(
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_hidewindowssecuritynotificationareacontrol",
                "device_vendor_msft_policy_config_windowsdefendersecuritycenter_hidewindowssecuritynotificationareacontrol_0", // Show
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Attack Surface Reduction Rules (L2)
fn generate_asr_rules_l2(args: &NewArgs) -> Value {
    // ASR rules must be in a GroupSettingCollectionInstance
    // L2 = Balanced mode: critical rules blocked, some warned, some audited
    let asr_rules = vec![
        // Block execution of potentially obfuscated scripts (PowerShell/JS/VBS) = warn
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_warn",
        ),
        // Block Win32 API calls from Office macros = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros_block",
        ),
        // Block executable files from running unless they meet prevalence, age, or trusted list criterion = audit
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion_audit",
        ),
        // Block Office communication apps from creating child processes = warn
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses_warn",
        ),
        // Block all Office applications from creating child processes = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses_block",
        ),
        // Block Adobe Reader from creating child processes = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses_block",
        ),
        // Block credential stealing from Windows local security authority subsystem (lsass.exe) = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_block",
        ),
        // Block JavaScript or VBScript from launching downloaded executable content = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent_block",
        ),
        // Block untrusted and unsigned processes that run from USB = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb_block",
        ),
        // Block persistence through WMI event subscription = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription_block",
        ),
        // Block use of copied or impersonated system tools = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools_block",
        ),
        // Block abuse of exploited vulnerable signed drivers = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers_block",
        ),
        // Block process creations originating from PSExec and WMI commands = warn
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands_warn",
        ),
        // Block Office applications from creating executable content = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent_block",
        ),
        // Block Office applications from injecting code into other processes = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses_block",
        ),
        // Block rebooting machine in Safe Mode = audit
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode_audit",
        ),
        // Use advanced protection against ransomware = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware_block",
        ),
        // Block executable content from email client and webmail = block
        choice_setting(
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail",
            "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail_block",
        ),
    ];

    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Attack Surface Reduction - D - ASR Rules (L2)", args.name),
        description: "Attack Surface Reduction rules in Block/Warn/Audit mode (L2 = Balanced) - DO NOT ASSIGN WITHOUT VALIDATING VIA AUDIT MODE FIRST! https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-operationalize".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: Some(TemplateReference {
            template_id: "e8c053d6-9f95-42b1-a7f1-ebfd71c67a4b_1".to_string(),
            template_family: TemplateFamily::EndpointSecurityAttackSurfaceReduction,
            template_display_name: "Attack Surface Reduction Rules".to_string(),
            template_display_version: "Version 1".to_string(),
        }),
        settings: vec![
            // ASR rules wrapped in GroupSettingCollectionInstance
            group_collection_setting(
                "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                vec![asr_rules], // Single collection item containing all 18 rules
            ),
            // Controlled Folder Access (separate choice setting)
            choice_setting(
                "device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess",
                "device_vendor_msft_policy_config_defender_enablecontrolledfolderaccess_2", // Enabled (Block mode)
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Windows Firewall
fn generate_windows_firewall_configuration(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!(
            "{} - OIB - ES - Windows Firewall - D - Firewall Configuration",
            args.name
        ),
        description:
            "Windows Defender Firewall - Enabled for all profiles with auditing - Windows 11 25H2"
                .to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            // Audit filtering platform connection
            choice_setting(
                "device_vendor_msft_policy_config_audit_objectaccess_auditfilteringplatformconnection",
                "device_vendor_msft_policy_config_audit_objectaccess_auditfilteringplatformconnection_2", // Success and Failure
            ),
            // Audit filtering platform packet drop
            choice_setting(
                "device_vendor_msft_policy_config_audit_objectaccess_auditfilteringplatformpacketdrop",
                "device_vendor_msft_policy_config_audit_objectaccess_auditfilteringplatformpacketdrop_2", // Success and Failure
            ),
            // Disable stateful FTP
            choice_setting(
                "vendor_msft_firewall_mdmstore_global_disablestatefulftp",
                "vendor_msft_firewall_mdmstore_global_disablestatefulftp_true",
            ),
            // Enable firewall - Domain profile
            choice_setting(
                "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall",
                "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall_true",
            ),
            // Enable firewall - Private profile
            choice_setting(
                "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall",
                "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall_true",
            ),
            // Enable firewall - Public profile
            choice_setting(
                "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall",
                "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall_true",
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Windows Hello for Business
fn generate_windows_hello_for_business(args: &NewArgs) -> Value {
    // Windows Hello for Business main configuration (GroupSettingCollectionInstance)
    let whfb_config = vec![
        // Require security device (TPM) for Windows Hello
        choice_setting(
            "device_vendor_msft_passportforwork_{tenantid}_policies_requiresecuritydevice",
            "device_vendor_msft_passportforwork_{tenantid}_policies_requiresecuritydevice_true",
        ),
        // Enable Windows Hello for Business
        choice_setting(
            "device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork",
            "device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork_true",
        ),
        // Minimum PIN length = 6
        integer_setting(
            "device_vendor_msft_passportforwork_{tenantid}_policies_pincomplexity_minimumpinlength",
            6,
        ),
        // Use certificate for on-prem auth = false (use key-based auth)
        choice_setting(
            "device_vendor_msft_passportforwork_{tenantid}_policies_usecertificateforonpremauth",
            "device_vendor_msft_passportforwork_{tenantid}_policies_usecertificateforonpremauth_false",
        ),
        // Enable PIN recovery
        choice_setting(
            "device_vendor_msft_passportforwork_{tenantid}_policies_enablepinrecovery",
            "device_vendor_msft_passportforwork_{tenantid}_policies_enablepinrecovery_true",
        ),
    ];

    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Windows Hello for Business - D - WHfB Configuration", args.name),
        description: "Passwordless authentication via Windows Hello for Business PIN/biometrics with TPM security device".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            // Main WHfB configuration wrapped in GroupSettingCollectionInstance
            group_collection_setting(
                "device_vendor_msft_passportforwork_{tenantid}",
                vec![whfb_config],
            ),
            // Facial features enhanced anti-spoofing (separate choice setting)
            choice_setting(
                "device_vendor_msft_passportforwork_biometrics_facialfeaturesuseenhancedantispoofing",
                "device_vendor_msft_passportforwork_biometrics_facialfeaturesuseenhancedantispoofing_true",
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Windows LAPS
fn generate_windows_laps_configuration(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - ES - Windows LAPS - D - LAPS Configuration (24H2+)", args.name),
        description: "Windows Local Administrator Password Solution - automated local admin password rotation with Azure AD backup".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            // Backup directory: Azure AD (1 = Azure AD, 0 = On-prem AD, 2 = Both)
            choice_setting(
                "device_vendor_msft_laps_policies_backupdirectory",
                "device_vendor_msft_laps_policies_backupdirectory_1",
            ),
            // Password complexity: Large letters + small letters + numbers + special characters (8 = all complexity)
            choice_setting(
                "device_vendor_msft_laps_policies_passwordcomplexity",
                "device_vendor_msft_laps_policies_passwordcomplexity_8",
            ),
            // Password length: 21 characters
            integer_setting("device_vendor_msft_laps_policies_passwordlength", 21),
            // Post-authentication actions: Reset password and logoff managed account (11)
            choice_setting(
                "device_vendor_msft_laps_policies_postauthenticationactions",
                "device_vendor_msft_laps_policies_postauthenticationactions_11",
            ),
            // Post-authentication reset delay: 1 hour
            integer_setting("device_vendor_msft_laps_policies_postauthenticationresetdelay", 1),
            // Automatic account management enabled: true
            choice_setting(
                "device_vendor_msft_laps_policies_automaticaccountmanagementenabled",
                "device_vendor_msft_laps_policies_automaticaccountmanagementenabled_true",
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Credential Management (Passwordless)
fn generate_credential_management_passwordless(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!(
            "{} - SC - Credential Management - D - Passwordless - v3.3",
            args.name
        ),
        description: "Enforces passwordless authentication patterns".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            choice_setting(
                "device_vendor_msft_policy_config_admx_credentialproviders_defaultcredentialprovider",
                "device_vendor_msft_policy_config_admx_credentialproviders_defaultcredentialprovider_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_authentication_enablepasswordlessexperience",
                "device_vendor_msft_policy_config_authentication_enablepasswordlessexperience_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_authentication_enablewebsignin",
                "device_vendor_msft_policy_config_authentication_enablewebsignin_1",
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Device Security - Security Hardening (80 settings)
fn generate_device_security_hardening(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - SC - Device Security - D - Security Hardening - v3.7", args.name),
        description: "General security hardening settings (credential guard, remote desktop, SMB, network security, etc.)".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            choice_setting("device_vendor_msft_policy_config_mssecurityguide_applyuacrestrictionstolocalaccountsonnetworklogon",
                          "device_vendor_msft_policy_config_mssecurityguide_applyuacrestrictionstolocalaccountsonnetworklogon_1"),
            choice_setting("device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver",
                          "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver_1"),
            choice_setting("device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server",
                          "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server_0"),
            choice_setting("device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection",
                          "device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection_1"),
            choice_setting("device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel",
                          "device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel_1"),
            choice_setting("device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel",
                          "device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel_1"),
            choice_setting("device_vendor_msft_policy_config_msslegacy_allowicmpredirectstooverrideospfgeneratedroutes",
                          "device_vendor_msft_policy_config_msslegacy_allowicmpredirectstooverrideospfgeneratedroutes_0"),
            choice_setting("device_vendor_msft_policy_config_msslegacy_allowthecomputertoignorenetbiosnamereleaserequestsexceptfromwinsservers",
                          "device_vendor_msft_policy_config_msslegacy_allowthecomputertoignorenetbiosnamereleaserequestsexceptfromwinsservers_1"),
            choice_setting("device_vendor_msft_policy_config_admx_mss-legacy_pol_mss_screensavergraceperiod",
                          "device_vendor_msft_policy_config_admx_mss-legacy_pol_mss_screensavergraceperiod_1"),
            choice_setting("device_vendor_msft_policy_config_connectivity_prohibitinstallationandconfigurationofnetworkbridge",
                          "device_vendor_msft_policy_config_connectivity_prohibitinstallationandconfigurationofnetworkbridge_1"),
            choice_setting("device_vendor_msft_policy_config_admx_networkconnections_nc_stddomainusersetlocation",
                          "device_vendor_msft_policy_config_admx_networkconnections_nc_stddomainusersetlocation_1"),
            choice_setting("device_vendor_msft_policy_config_admx_wcm_wcm_minimizeconnections",
                          "device_vendor_msft_policy_config_admx_wcm_wcm_minimizeconnections_1"),
            choice_setting("device_vendor_msft_policy_config_windowsconnectionmanager_prohitconnectiontonondomainnetworkswhenconnectedtodomainauthenticatednetwork",
                          "device_vendor_msft_policy_config_windowsconnectionmanager_prohitconnectiontonondomainnetworkswhenconnectedtodomainauthenticatednetwork_1"),
            choice_setting("device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle",
                          "device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle_1"),
            choice_setting("device_vendor_msft_policy_config_credentialsdelegation_remotehostallowsdelegationofnonexportablecredentials",
                          "device_vendor_msft_policy_config_credentialsdelegation_remotehostallowsdelegationofnonexportablecredentials_1"),
            choice_setting("device_vendor_msft_policy_config_system_bootstartdriverinitialization",
                          "device_vendor_msft_policy_config_system_bootstartdriverinitialization_1"),
            choice_setting("device_vendor_msft_policy_config_connectivity_disabledownloadingofprintdriversoverhttp",
                          "device_vendor_msft_policy_config_connectivity_disabledownloadingofprintdriversoverhttp_1"),
            choice_setting("device_vendor_msft_policy_config_connectivity_disableinternetdownloadforwebpublishingandonlineorderingwizards",
                          "device_vendor_msft_policy_config_connectivity_disableinternetdownloadforwebpublishingandonlineorderingwizards_1"),
            choice_setting("device_vendor_msft_policy_config_remoteassistance_unsolicitedremoteassistance",
                          "device_vendor_msft_policy_config_remoteassistance_unsolicitedremoteassistance_0"),
            choice_setting("device_vendor_msft_policy_config_remoteassistance_solicitedremoteassistance",
                          "device_vendor_msft_policy_config_remoteassistance_solicitedremoteassistance_0"),
            choice_setting("device_vendor_msft_policy_config_autoplay_disallowautoplayfornonvolumedevices",
                          "device_vendor_msft_policy_config_autoplay_disallowautoplayfornonvolumedevices_1"),
            choice_setting("device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior",
                          "device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_1"),
            choice_setting("device_vendor_msft_policy_config_autoplay_turnoffautoplay",
                          "device_vendor_msft_policy_config_autoplay_turnoffautoplay_1"),
            choice_setting("device_vendor_msft_policy_config_credentialsui_enumerateadministrators",
                          "device_vendor_msft_policy_config_credentialsui_enumerateadministrators_0"),
            choice_setting("device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen",
                          "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen_1"),
            choice_setting("device_vendor_msft_policy_config_fileexplorer_turnoffdataexecutionpreventionforexplorer",
                          "device_vendor_msft_policy_config_fileexplorer_turnoffdataexecutionpreventionforexplorer_0"),
            choice_setting("device_vendor_msft_policy_config_fileexplorer_turnoffheapterminationoncorruption",
                          "device_vendor_msft_policy_config_fileexplorer_turnoffheapterminationoncorruption_0"),
            choice_setting("device_vendor_msft_policy_config_admx_sharing_disablehomegroup",
                          "device_vendor_msft_policy_config_admx_sharing_disablehomegroup_1"),
            choice_setting("device_vendor_msft_policy_config_internetexplorer_disableinternetexplorerapp_v2",
                          "device_vendor_msft_policy_config_internetexplorer_disableinternetexplorerapp_v2_1"),
            choice_setting("device_vendor_msft_policy_config_admx_pushtoinstall_disablepushtoinstall",
                          "device_vendor_msft_policy_config_admx_pushtoinstall_disablepushtoinstall_1"),
            choice_setting("device_vendor_msft_policy_config_internetexplorer_disableenclosuredownloading",
                          "device_vendor_msft_policy_config_internetexplorer_disableenclosuredownloading_1"),
            choice_setting("device_vendor_msft_policy_config_errorreporting_disablewindowserrorreporting",
                          "device_vendor_msft_policy_config_errorreporting_disablewindowserrorreporting_0"),
            choice_setting("device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging",
                          "device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging_1"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_client",
                          "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_client_0"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_client",
                          "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_client_0"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_disallowdigestauthentication",
                          "device_vendor_msft_policy_config_remotemanagement_disallowdigestauthentication_1"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_service",
                          "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_service_0"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_service",
                          "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_service_0"),
            choice_setting("device_vendor_msft_policy_config_remotemanagement_disallowstoringofrunascredentials",
                          "device_vendor_msft_policy_config_remotemanagement_disallowstoringofrunascredentials_1"),
            choice_setting("device_vendor_msft_policy_config_connectivity_allowphonepclinking",
                          "device_vendor_msft_policy_config_connectivity_allowphonepclinking_0"),
            choice_setting("device_vendor_msft_policy_config_dataprotection_allowdirectmemoryaccess",
                          "device_vendor_msft_policy_config_dataprotection_allowdirectmemoryaccess_0"),
            choice_setting("device_vendor_msft_policy_config_experience_allowcortana",
                          "device_vendor_msft_policy_config_experience_allowcortana_0"),
            choice_setting("device_vendor_msft_policy_config_experience_allowmanualmdmunenrollment",
                          "device_vendor_msft_policy_config_experience_allowmanualmdmunenrollment_0"),
            choice_setting("device_vendor_msft_policy_config_games_allowadvancedgamingservices",
                          "device_vendor_msft_policy_config_games_allowadvancedgamingservices_0"),
            choice_setting("device_vendor_msft_policy_config_kerberos_pkinithashalgorithmconfiguration",
                          "device_vendor_msft_policy_config_kerberos_pkinithashalgorithmconfiguration_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_auditclientdoesnotsupportencryption",
                          "device_vendor_msft_policy_config_lanmanserver_auditclientdoesnotsupportencryption_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_auditclientdoesnotsupportsigning",
                          "device_vendor_msft_policy_config_lanmanserver_auditclientdoesnotsupportsigning_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_auditinsecureguestlogon",
                          "device_vendor_msft_policy_config_lanmanserver_auditinsecureguestlogon_1"),
            integer_setting("device_vendor_msft_policy_config_lanmanserver_authratelimiterdelayinms", 2000),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_enableauthratelimiter",
                          "device_vendor_msft_policy_config_lanmanserver_enableauthratelimiter_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_enablemailslots",
                          "device_vendor_msft_policy_config_lanmanserver_enablemailslots_0"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_maxsmb2dialect",
                          "device_vendor_msft_policy_config_lanmanserver_maxsmb2dialect_785"),
            choice_setting("device_vendor_msft_policy_config_lanmanserver_minsmb2dialect",
                          "device_vendor_msft_policy_config_lanmanserver_minsmb2dialect_768"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_auditinsecureguestlogon",
                          "device_vendor_msft_policy_config_lanmanworkstation_auditinsecureguestlogon_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_auditserverdoesnotsupportencryption",
                          "device_vendor_msft_policy_config_lanmanworkstation_auditserverdoesnotsupportencryption_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_auditserverdoesnotsupportsigning",
                          "device_vendor_msft_policy_config_lanmanworkstation_auditserverdoesnotsupportsigning_1"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_enableinsecureguestlogons",
                          "device_vendor_msft_policy_config_lanmanworkstation_enableinsecureguestlogons_0"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_enablemailslots",
                          "device_vendor_msft_policy_config_lanmanworkstation_enablemailslots_0"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_maxsmb2dialect",
                          "device_vendor_msft_policy_config_lanmanworkstation_maxsmb2dialect_785"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_minsmb2dialect",
                          "device_vendor_msft_policy_config_lanmanworkstation_minsmb2dialect_768"),
            choice_setting("device_vendor_msft_policy_config_lanmanworkstation_requireencryption",
                          "device_vendor_msft_policy_config_lanmanworkstation_requireencryption_0"),
            choice_setting("device_vendor_msft_policy_config_privacy_disableprivacyexperience",
                          "device_vendor_msft_policy_config_privacy_disableprivacyexperience_1"),
            choice_setting("device_vendor_msft_policy_config_security_allowaddprovisioningpackage",
                          "device_vendor_msft_policy_config_security_allowaddprovisioningpackage_0"),
            choice_setting("device_vendor_msft_policy_config_security_allowremoveprovisioningpackage",
                          "device_vendor_msft_policy_config_security_allowremoveprovisioningpackage_0"),
            choice_setting("device_vendor_msft_policy_config_security_requireretrievehealthcertificateonboot",
                          "device_vendor_msft_policy_config_security_requireretrievehealthcertificateonboot_1"),
            string_setting("device_vendor_msft_policy_config_settings_pagevisibilitylist", "hide:gaming-gamebar;gaming-gamedvr;gaming-broadcasting;gaming-gamemode;gaming-xboxnetworking"),
            choice_setting("device_vendor_msft_policy_config_smartscreen_enablesmartscreeninshell",
                          "device_vendor_msft_policy_config_smartscreen_enablesmartscreeninshell_1"),
            choice_setting("device_vendor_msft_policy_config_smartscreen_preventoverrideforfilesinshell",
                          "device_vendor_msft_policy_config_smartscreen_preventoverrideforfilesinshell_1"),
            choice_setting("device_vendor_msft_policy_config_sudo_enablesudo",
                          "device_vendor_msft_policy_config_sudo_enablesudo_0"),
            choice_setting("device_vendor_msft_policy_config_systemservices_configurexboxaccessorymanagementservicestartupmode",
                          "device_vendor_msft_policy_config_systemservices_configurexboxaccessorymanagementservicestartupmode_4"),
            choice_setting("device_vendor_msft_policy_config_systemservices_configurexboxliveauthmanagerservicestartupmode",
                          "device_vendor_msft_policy_config_systemservices_configurexboxliveauthmanagerservicestartupmode_4"),
            choice_setting("device_vendor_msft_policy_config_systemservices_configurexboxlivegamesaveservicestartupmode",
                          "device_vendor_msft_policy_config_systemservices_configurexboxlivegamesaveservicestartupmode_4"),
            choice_setting("device_vendor_msft_policy_config_systemservices_configurexboxlivenetworkingservicestartupmode",
                          "device_vendor_msft_policy_config_systemservices_configurexboxlivenetworkingservicestartupmode_4"),
            choice_setting("device_vendor_msft_policy_config_taskscheduler_enablexboxgamesavetask",
                          "device_vendor_msft_policy_config_taskscheduler_enablexboxgamesavetask_0"),
            choice_setting("device_vendor_msft_policy_config_wifi_allowautoconnecttowifisensehotspots",
                          "device_vendor_msft_policy_config_wifi_allowautoconnecttowifisensehotspots_0"),
            choice_setting("device_vendor_msft_policy_config_wifi_allowinternetsharing",
                          "device_vendor_msft_policy_config_wifi_allowinternetsharing_0"),
            choice_setting("device_vendor_msft_policy_config_windowsinkworkspace_allowwindowsinkworkspace",
                          "device_vendor_msft_policy_config_windowsinkworkspace_allowwindowsinkworkspace_1"),
            choice_setting("device_vendor_msft_policy_config_wirelessdisplay_allowprojectionfrompc",
                          "device_vendor_msft_policy_config_wirelessdisplay_allowprojectionfrompc_1"),
            choice_setting("device_vendor_msft_policy_config_wirelessdisplay_allowprojectiontopc",
                          "device_vendor_msft_policy_config_wirelessdisplay_allowprojectiontopc_0"),
            choice_setting("device_vendor_msft_policy_config_wirelessdisplay_requirepinforpairing",
                          "device_vendor_msft_policy_config_wirelessdisplay_requirepinforpairing_1"),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Device Security - Local Security Policies
fn generate_device_security_local_security_policies(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!(
            "{} - SC - Device Security - D - Local Security Policies (24H2+) - v3.6",
            args.name
        ),
        description: "UAC, account policies, audit policies, privilege escalation controls"
            .to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_enableadministratoraccountstatus",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_enableadministratoraccountstatus_0",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_enableguestaccountstatus",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_enableguestaccountstatus_0",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_smartcardremovalbehavior",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_smartcardremovalbehavior_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_sendunencryptedpasswordtothirdpartysmbservers",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_sendunencryptedpasswordtothirdpartysmbservers_0",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsalways",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsalways_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccounts",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccounts_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccountsandshares",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccountsandshares_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictanonymousaccesstonamedpipesandshares",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictanonymousaccesstonamedpipesandshares_1",
            ),
            string_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictclientsallowedtomakeremotecallstosam",
                "O:BAG:BAD:(A;;RC;;;BA)",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_donotstorelanmanagerhashvalueonnextpasswordchange",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_donotstorelanmanagerhashvalueonnextpasswordchange_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_lanmanagerauthenticationlevel",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_lanmanagerauthenticationlevel_5",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedclients",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedclients_537395200",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedservers",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedservers_537395200",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforadministrators",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforadministrators_2",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforstandardusers",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforstandardusers_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_detectapplicationinstallationsandpromptforelevation",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_detectapplicationinstallationsandpromptforelevation_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_onlyelevateuiaccessapplicationsthatareinstalledinsecurelocations",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_onlyelevateuiaccessapplicationsthatareinstalledinsecurelocations_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_switchtothesecuredesktopwhenpromptingforelevation",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_switchtothesecuredesktopwhenpromptingforelevation_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_useadminapprovalmode",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_useadminapprovalmode_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_virtualizefileandregistrywritefailurestoperuserlocations",
                "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_virtualizefileandregistrywritefailurestoperuserlocations_1",
            ),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Device Security - Login and Lock Screen
fn generate_device_security_login_and_lock_screen(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!("{} - OIB - SC - Device Security - D - Login and Lock Screen", args.name),
        description: "Lock screen hardening - disable Cortana, notifications, camera, password reveal - Windows 11 25H2".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            choice_setting("device_vendor_msft_policy_config_abovelock_allowcortanaabovelock", "device_vendor_msft_policy_config_abovelock_allowcortanaabovelock_0"),
            choice_setting("device_vendor_msft_policy_config_abovelock_allowtoasts", "device_vendor_msft_policy_config_abovelock_allowtoasts_0"),
            choice_setting("device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera", "device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera_1"),
            choice_setting("device_vendor_msft_policy_config_devicelock_preventlockscreenslideshow", "device_vendor_msft_policy_config_devicelock_preventlockscreenslideshow_1"),
            choice_setting("device_vendor_msft_policy_config_windowslogon_disablelockscreenappnotifications", "device_vendor_msft_policy_config_windowslogon_disablelockscreenappnotifications_1"),
            choice_setting("device_vendor_msft_policy_config_credentialsui_disablepasswordreveal", "device_vendor_msft_policy_config_credentialsui_disablepasswordreveal_1"),
            // TODO Phase 2: configautomaticrestartsignon requires child settings
            // choice_setting("device_vendor_msft_policy_config_windowslogon_configautomaticrestartsignon", "device_vendor_msft_policy_config_windowslogon_configautomaticrestartsignon_1"),
            choice_setting("device_vendor_msft_policy_config_windowslogon_allowautomaticrestartsignon", "device_vendor_msft_policy_config_windowslogon_allowautomaticrestartsignon_1"),
            choice_setting("device_vendor_msft_policy_config_authentication_allowaadpasswordreset", "device_vendor_msft_policy_config_authentication_allowaadpasswordreset_1"),
            choice_setting("device_vendor_msft_policy_config_privacy_letappsactivatewithvoiceabovelock", "device_vendor_msft_policy_config_privacy_letappsactivatewithvoiceabovelock_2"),
        ],
    };

    policy.to_json()
}

/// OIB Settings Catalog: Device Security - Power and Device Lock
fn generate_device_security_power_and_device_lock(args: &NewArgs) -> Value {
    let policy = SettingsCatalogPolicy {
        name: format!(
            "{} - SC - Device Security - U - Power and Device Lock - v3.6",
            args.name
        ),
        description: "Inactivity timeouts, power settings, screen lock requirements".to_string(),
        platform: Platform::Windows10,
        technologies: Technologies::Mdm,
        template_reference: None,
        settings: vec![
            choice_setting(
                "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakesonbattery",
                "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakesonbattery_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakespluggedin",
                "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakespluggedin_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_power_standbytimeoutonbattery",
                "device_vendor_msft_policy_config_power_standbytimeoutonbattery_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_power_standbytimeoutpluggedin",
                "device_vendor_msft_policy_config_power_standbytimeoutpluggedin_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_power_displayofftimeoutonbattery",
                "device_vendor_msft_policy_config_power_displayofftimeoutonbattery_1",
            ),
            choice_setting(
                "device_vendor_msft_policy_config_power_displayofftimeoutpluggedin",
                "device_vendor_msft_policy_config_power_displayofftimeoutpluggedin_1",
            ),
            integer_setting(
                "device_vendor_msft_policy_config_power_unattendedsleeptimeoutonbattery",
                600,
            ),
            integer_setting(
                "device_vendor_msft_policy_config_power_unattendedsleeptimeoutpluggedin",
                900,
            ),
        ],
    };

    policy.to_json()
}

/// Get CIS benchmark deviation rationale from OIB
fn get_cis_rationale() -> Vec<CISRationale> {
    vec![
        CISRationale {
            cis_ref: "3.5.1".to_string(),
            setting_name: "MSS: (AutoAdminLogon) Enable Automatic Logon".to_string(),
            rationale: "Breaks Autopilot".to_string(),
            notes: None,
        },
        CISRationale {
            cis_ref: "3.10.25.1".to_string(),
            setting_name: "Block user from showing account details on sign-in".to_string(),
            rationale: "Significantly impacts WHfB experience".to_string(),
            notes: None,
        },
        CISRationale {
            cis_ref: "45.7".to_string(),
            setting_name: "Interactive logon: Do not display last signed-in".to_string(),
            rationale:
                "Breaks Windows Hello by causing the user to always have to enter their credentials"
                    .to_string(),
            notes: None,
        },
        CISRationale {
            cis_ref: "45.8".to_string(),
            setting_name: "Interactive logon: Do not require CTRL+ALT+DEL".to_string(),
            rationale: "Significantly impacts WHfB experience".to_string(),
            notes: None,
        },
        // Add more as needed from OIBvsCIS-Rationale.csv
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args(name: &str, encryption: bool, defender: bool) -> NewArgs {
        NewArgs {
            platform: "windows".to_string(),
            encryption,
            defender,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: name.to_string(),
            template: "oib".to_string(),
        }
    }

    #[test]
    fn test_generate_oib_baseline_structure() {
        let args = create_test_args("Test OIB", true, true);
        let baseline = generate_oib_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "3.6");
        assert_eq!(baseline["template"], "OpenIntuneBaseline");
        assert_eq!(baseline["platform"], "windows");
        assert!(
            baseline["metadata"]["source"]
                .as_str()
                .unwrap()
                .contains("OpenIntuneBaseline")
        );
    }

    #[test]
    fn test_oib_baseline_policy_count_with_all_options() {
        let args = create_test_args("Test", true, true);
        let baseline = generate_oib_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // 4 compliance + BitLocker + 3 Defender + Firewall + WHfB + LAPS + 4 security = 15
        assert!(policies.len() >= 13);
    }

    #[test]
    fn test_oib_baseline_without_encryption() {
        let args = create_test_args("Test", false, true);
        let baseline = generate_oib_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // Should not include BitLocker
        let has_bitlocker = policies.iter().any(|p| {
            p["name"]
                .as_str()
                .map(|n| n.contains("BitLocker"))
                .unwrap_or(false)
        });
        assert!(!has_bitlocker);
    }

    #[test]
    fn test_oib_baseline_without_defender() {
        let args = create_test_args("Test", true, false);
        let baseline = generate_oib_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // Should not include Defender AV or ASR
        let has_defender_av = policies.iter().any(|p| {
            p["name"]
                .as_str()
                .map(|n| n.contains("Defender Antivirus"))
                .unwrap_or(false)
        });
        assert!(!has_defender_av);
    }

    #[test]
    fn test_compliance_defender_for_endpoint() {
        let args = create_test_args("Test", false, false);
        let policy = generate_compliance_defender_for_endpoint(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.windows10CompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("Defender for Endpoint")
        );
        assert_eq!(policy["deviceThreatProtectionEnabled"], true);
        assert_eq!(
            policy["deviceThreatProtectionRequiredSecurityLevel"],
            "medium"
        );
    }

    #[test]
    fn test_compliance_device_health() {
        let args = create_test_args("Test", false, false);
        let policy = generate_compliance_device_health(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.windows10CompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("Device Health")
        );
        assert_eq!(policy["secureBootEnabled"], true);
        assert_eq!(policy["codeIntegrityEnabled"], true);
    }

    #[test]
    fn test_compliance_device_security() {
        let args = create_test_args("Test", false, false);
        let policy = generate_compliance_device_security(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.windows10CompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("Device Security")
        );
        assert_eq!(policy["tpmRequired"], true);
        assert_eq!(policy["activeFirewallRequired"], true);
        assert_eq!(policy["antivirusRequired"], true);
    }

    #[test]
    fn test_compliance_password() {
        let args = create_test_args("Test", false, false);
        let policy = generate_compliance_password(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.windows10CompliancePolicy"
        );
        assert!(policy["displayName"].as_str().unwrap().contains("Password"));
        // Password is managed by Entra ID in OIB
        assert_eq!(policy["passwordRequired"], false);
    }

    #[test]
    fn test_bitlocker_settings_catalog() {
        let args = create_test_args("Test", true, false);
        let policy = generate_bitlocker_settings_catalog(&args);

        assert!(policy["name"].as_str().unwrap().contains("BitLocker"));
        assert!(
            policy["description"]
                .as_str()
                .unwrap()
                .contains("XTS-AES 256")
        );
        assert!(policy["settings"].is_array());
    }

    #[test]
    fn test_defender_antivirus_configuration() {
        let args = create_test_args("Test", false, true);
        let policy = generate_defender_antivirus_configuration(&args);

        assert!(
            policy["name"]
                .as_str()
                .unwrap()
                .contains("Defender Antivirus")
        );
        assert!(policy["settings"].is_array());
    }

    #[test]
    fn test_asr_rules_l2() {
        let args = create_test_args("Test", false, true);
        let policy = generate_asr_rules_l2(&args);

        assert!(policy["name"].as_str().unwrap().contains("ASR Rules"));
        assert!(
            policy["description"]
                .as_str()
                .unwrap()
                .contains("Block/Warn/Audit")
        );
    }

    #[test]
    fn test_windows_firewall_configuration() {
        let args = create_test_args("Test", false, false);
        let policy = generate_windows_firewall_configuration(&args);

        assert!(policy["name"].as_str().unwrap().contains("Firewall"));
        assert!(policy["settings"].is_array());
    }

    #[test]
    fn test_windows_hello_for_business() {
        let args = create_test_args("Test", false, false);
        let policy = generate_windows_hello_for_business(&args);

        assert!(policy["name"].as_str().unwrap().contains("Windows Hello"));
        assert!(
            policy["description"]
                .as_str()
                .unwrap()
                .contains("Passwordless")
        );
    }

    #[test]
    fn test_windows_laps_configuration() {
        let args = create_test_args("Test", false, false);
        let policy = generate_windows_laps_configuration(&args);

        assert!(policy["name"].as_str().unwrap().contains("LAPS"));
        assert!(
            policy["description"]
                .as_str()
                .unwrap()
                .contains("Local Administrator Password")
        );
    }

    #[test]
    fn test_device_security_hardening() {
        let args = create_test_args("Test", false, false);
        let policy = generate_device_security_hardening(&args);

        assert!(
            policy["name"]
                .as_str()
                .unwrap()
                .contains("Security Hardening")
        );
        assert!(policy["settings"].is_array());
        let settings = policy["settings"].as_array().unwrap();
        // Should have many hardening settings
        assert!(settings.len() > 30);
    }

    #[test]
    fn test_device_security_local_security_policies() {
        let args = create_test_args("Test", false, false);
        let policy = generate_device_security_local_security_policies(&args);

        assert!(
            policy["name"]
                .as_str()
                .unwrap()
                .contains("Local Security Policies")
        );
        assert!(policy["description"].as_str().unwrap().contains("UAC"));
    }

    #[test]
    fn test_device_security_login_and_lock_screen() {
        let args = create_test_args("Test", false, false);
        let policy = generate_device_security_login_and_lock_screen(&args);

        assert!(
            policy["name"]
                .as_str()
                .unwrap()
                .contains("Login and Lock Screen")
        );
    }

    #[test]
    fn test_device_security_power_and_device_lock() {
        let args = create_test_args("Test", false, false);
        let policy = generate_device_security_power_and_device_lock(&args);

        assert!(policy["name"].as_str().unwrap().contains("Power"));
        assert!(
            policy["description"]
                .as_str()
                .unwrap()
                .contains("Inactivity")
        );
    }

    #[test]
    fn test_cis_rationale_not_empty() {
        let rationale = get_cis_rationale();
        assert!(!rationale.is_empty());
        assert!(rationale.len() >= 4);
    }

    #[test]
    fn test_cis_rationale_structure() {
        let rationale = get_cis_rationale();
        for item in &rationale {
            assert!(!item.cis_ref.is_empty());
            assert!(!item.setting_name.is_empty());
            assert!(!item.rationale.is_empty());
        }
    }
}
