//! Android Baseline Configuration
//!
//! Comprehensive Android device management supporting:
//! - Android Enterprise Work Profile (BYOD)
//! - Fully Managed Devices (Corporate Owned)
//! - Compliance policies
//! - Device configuration
//! - App protection policies (MAM)
//!
//! Based on Android Enterprise and OpenIntuneBaseline best practices

#![allow(dead_code)]

use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use serde_json::{Value, json};

/// Generate Android baseline with compliance + configuration + app protection
pub fn generate_android_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Compliance Policies - Work Profile
    policies.push(generate_android_work_profile_compliance(args));

    // Compliance Policies - Fully Managed
    policies.push(generate_android_fully_managed_compliance(args));

    // Device Configuration - Work Profile
    policies.push(generate_android_work_profile_restrictions(args));

    // Device Configuration - Fully Managed
    policies.push(generate_android_fully_managed_restrictions(args));

    // App Protection Policy (MAM)
    policies.push(generate_android_app_protection_policy(args));

    // Email Profile
    policies.push(generate_android_email_profile(args));

    // WiFi Profile (optional example)
    policies.push(generate_android_wifi_profile(args));

    // Conditional: Defender for Endpoint
    if args.defender {
        policies.push(generate_android_defender_policy(args));
    }

    Ok(json!({
        "version": "1.0",
        "template": "android-baseline",
        "platform": "Android",
        "metadata": {
            "description": "Android Enterprise management baseline (Work Profile + Fully Managed)",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &args.name,
            "policies_count": policies.len()
        },
        "policies": policies
    }))
}

/// Android Work Profile Compliance (BYOD scenario)
fn generate_android_work_profile_compliance(args: &NewArgs) -> Value {
    let min_os = args.min_os.as_deref().unwrap_or("10.0"); // Android 10+

    json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileCompliancePolicy",
        "displayName": format!("{} - Android Work Profile Compliance", args.name),
        "description": "Compliance requirements for Android Enterprise Work Profile devices (BYOD)",

        // OS Version
        "osMinimumVersion": min_os,
        "osMaximumVersion": null,

        // Security
        "passwordRequired": true,
        "passwordMinimumLength": 6,
        "passwordRequiredType": "numericComplex", // deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex
        "passwordMinutesOfInactivityBeforeLock": 5,
        "passwordExpirationDays": null,
        "passwordPreviousPasswordBlockCount": 5,

        // Device Security
        "securityRequireSafetyNetAttestationBasicIntegrity": true,
        "securityRequireSafetyNetAttestationCertifiedDevice": false, // More strict
        "securityBlockJailbrokenDevices": true,
        "securityPreventInstallAppsFromUnknownSources": true,
        "securityDisableUsbDebugging": true,
        "securityRequireVerifyApps": true,

        // Encryption
        "storageRequireEncryption": true,

        // Device Threat Protection
        "deviceThreatProtectionEnabled": args.defender,
        "deviceThreatProtectionRequiredSecurityLevel": "medium", // unavailable, secured, low, medium, high, notSet

        // Work Profile
        "workProfileDataSharingType": "preventAny", // deviceDefault, preventAny, allowPersonalToWork, noRestriction
        "workProfileBlockNotificationsWhileDeviceLocked": false,

        // Actions for noncompliance
        "scheduledActionsForRule": [{
            "ruleName": "PasswordRequired",
            "scheduledActionConfigurations": [{
                "actionType": "block",
                "gracePeriodHours": 0,
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }]
    })
}

/// Android Fully Managed Compliance (Corporate Owned)
fn generate_android_fully_managed_compliance(args: &NewArgs) -> Value {
    let min_os = args.min_os.as_deref().unwrap_or("10.0");

    json!({
        "@odata.type": "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
        "displayName": format!("{} - Android Fully Managed Compliance", args.name),
        "description": "Compliance requirements for Android Enterprise Fully Managed devices (Corporate Owned)",

        // OS Version
        "osMinimumVersion": min_os,
        "osMaximumVersion": null,

        // Security
        "passwordRequired": true,
        "passwordMinimumLength": 8,
        "passwordRequiredType": "numericComplex",
        "passwordMinutesOfInactivityBeforeLock": 5,
        "passwordExpirationDays": 365,
        "passwordPreviousPasswordBlockCount": 5,

        // Advanced Security
        "securityRequireSafetyNetAttestationBasicIntegrity": true,
        "securityRequireSafetyNetAttestationCertifiedDevice": true, // Stricter for corporate
        "securityBlockJailbrokenDevices": true,
        "securityRequireVerifyApps": true,
        "securityRequireCompanyPortalAppIntegrity": true,

        // Encryption
        "storageRequireEncryption": true,
        "advancedThreatProtectionRequiredSecurityLevel": "medium",

        // Actions
        "scheduledActionsForRule": [{
            "ruleName": "PasswordRequired",
            "scheduledActionConfigurations": [{
                "actionType": "block",
                "gracePeriodHours": 0
            }]
        }]
    })
}

/// Android Work Profile Device Restrictions
fn generate_android_work_profile_restrictions(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration",
        "displayName": format!("{} - Android Work Profile Restrictions", args.name),
        "description": "Device restrictions for Android Enterprise Work Profile",

        // Password
        "passwordBlockFingerprintUnlock": false,
        "passwordBlockTrustAgents": false,
        "passwordExpirationDays": null,
        "passwordMinimumLength": 6,
        "passwordMinutesOfInactivityBeforeScreenTimeout": 5,
        "passwordPreviousPasswordBlockCount": 5,
        "passwordRequiredType": "numericComplex",
        "passwordSignInFailureCountBeforeFactoryReset": 11,

        // Work Profile
        "workProfileDataSharingType": "preventAny", // Prevent data sharing between work and personal
        "workProfileBlockNotificationsWhileDeviceLocked": false,
        "workProfileBlockAddingAccounts": false,
        "workProfileBluetoothEnableContactSharing": false,
        "workProfileBlockScreenCapture": false,
        "workProfileBlockCrossProfileCallerId": false,
        "workProfileBlockCamera": false,
        "workProfileBlockCrossProfileContactsSearch": false,
        "workProfileBlockCrossProfileCopyPaste": true, // Block copy/paste between work and personal
        "workProfileDefaultAppPermissionPolicy": "prompt", // prompt, autoGrant, autoDeny
        "workProfilePasswordBlockFingerprintUnlock": false,
        "workProfilePasswordBlockTrustAgents": false,
        "workProfilePasswordRequiredType": "numericComplex",
        "workProfilePasswordMinimumLength": 6,
        "workProfileRequirePassword": true,

        // Security
        "securityRequireVerifyApps": true
    })
}

/// Android Fully Managed Device Restrictions
fn generate_android_fully_managed_restrictions(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration",
        "displayName": format!("{} - Android Fully Managed Restrictions", args.name),
        "description": "Device restrictions for Android Enterprise Fully Managed devices",

        // Password
        "passwordBlockTrustAgents": false,
        "passwordExpirationDays": 365,
        "passwordMinimumLength": 8,
        "passwordMinutesOfInactivityBeforeScreenTimeout": 5,
        "passwordPreviousPasswordBlockCount": 5,
        "passwordRequiredType": "numericComplex",
        "passwordSignInFailureCountBeforeFactoryReset": 11,
        "passwordBlockFingerprintUnlock": false,

        // Apps
        "appsBlockInstallFromUnknownSources": true,
        "appsAutoUpdatePolicy": "notConfigured", // notConfigured, userChoice, never, wiFiOnly, always
        "appsDefaultPermissionPolicy": "prompt", // deviceDefault, prompt, autoGrant, autoDeny

        // Camera and Screen
        "cameraBlocked": false,
        "screenCaptureBlocked": false,

        // Factory Reset Protection
        "factoryResetBlocked": true,
        "factoryResetDeviceAdministratorEmails": [],

        // Google Play Store
        "playStoreMode": "allowList", // notConfigured, allowList, blockList
        "appsInPrivateStore": [], // List of approved apps

        // Location
        "locationServicesBlocked": false,

        // Network
        "networkEscapeHatchAllowed": false,
        "nfcBlockOutgoingBeam": false,
        "bluetoothBlocked": false,
        "bluetoothBlockConfiguration": false,
        "bluetoothBlockContactSharing": false,
        "wifiBlocked": false,
        "wifiBlockEditConfigurations": false,

        // USB
        "usbFileTransferBlocked": false,
        "usbDebuggingBlocked": true, // Block USB debugging

        // System
        "systemUpdateWindowStartMinutesAfterMidnight": 120, // 2 AM
        "systemUpdateWindowEndMinutesAfterMidnight": 360,   // 6 AM
        "systemUpdateInstallType": "automatic", // deviceDefault, postpone, windowed, automatic

        // Personal Usage on Corporate Device
        "personalProfileAppsAllowInstallFromUnknownSources": false,
        "personalProfileCameraBlocked": false,
        "personalProfileScreenCaptureBlocked": false,

        // Kiosk Mode (optional - commented out)
        // "kioskModeApps": [],
        // "kioskModeAppOrderEnabled": false,
        // "kioskModeAppPositions": [],

        // Security
        "securityRequireVerifyApps": true,
        "deviceOwnerLockScreenInfo": {
            "enabled": true,
            "phoneNumber": null,
            "message": "This device is managed by your organization. If lost, contact IT."
        }
    })
}

/// Android App Protection Policy (MAM)
fn generate_android_app_protection_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidManagedAppProtection",
        "displayName": format!("{} - Android App Protection Policy", args.name),
        "description": "App protection policy (MAM) for managed apps on Android",

        // Apps covered
        "apps": [
            {
                "id": "com.microsoft.office.outlook",
                "version": "*"
            },
            {
                "id": "com.microsoft.office.word",
                "version": "*"
            },
            {
                "id": "com.microsoft.office.excel",
                "version": "*"
            },
            {
                "id": "com.microsoft.office.powerpoint",
                "version": "*"
            },
            {
                "id": "com.microsoft.teams",
                "version": "*"
            },
            {
                "id": "com.microsoft.skydrive",
                "version": "*" // OneDrive
            },
            {
                "id": "com.microsoft.sharepoint",
                "version": "*"
            },
            {
                "id": "com.microsoft.emmx",
                "version": "*" // Edge
            }
        ],

        // Data Protection
        "dataBackupBlocked": true,
        "deviceComplianceRequired": true,
        "managedBrowserToOpenLinksRequired": true,
        "saveAsBlocked": false,
        "periodOfflineBeforeAccessCheck": "PT12H",
        "periodOnlineBeforeAccessCheck": "PT30M",
        "allowedInboundDataTransferSources": "managedApps",
        "allowedOutboundClipboardSharingLevel": "managedAppsWithPasteIn",
        "allowedOutboundDataTransferDestinations": "managedApps",
        "organizationalCredentialsRequired": false,
        "contactSyncBlocked": false,
        "printBlocked": false,
        "fingerprintBlocked": false,

        // Encryption
        "encryptAppData": true,

        // Access Requirements
        "pinRequired": true,
        "pinCharacterSet": "alphanumericAndSymbol",
        "minimumPinLength": 6,
        "maximumPinRetries": 5,
        "simplePinBlocked": true,
        "minimumRequiredOsVersion": "10.0",
        "minimumWarningOsVersion": "10.0",
        "minimumRequiredAppVersion": null,
        "minimumWarningAppVersion": null,
        "managedBrowser": "microsoftEdge",

        // Conditional Launch
        "periodOfflineBeforeWipeIsEnforced": "P90D",
        "periodBeforePinReset": "P0D",

        // Android-specific
        "screenCaptureBlocked": false,
        "disableAppEncryptionIfDeviceEncryptionIsEnabled": false,
        "minimumRequiredPatchVersion": null,
        "minimumWarningPatchVersion": null,
        "minimumWipeSdkVersion": null,
        "minimumWipePatchVersion": null,
        "allowedAndroidDeviceManufacturers": "", // Empty = all manufacturers
        "appActionIfAndroidDeviceManufacturerNotAllowed": "block",
        "requiredAndroidSafetyNetDeviceAttestationType": "basicIntegrity", // none, basicIntegrity, basicIntegrityAndDeviceCertification
        "appActionIfAndroidSafetyNetDeviceAttestationFailed": "block",
        "requiredAndroidSafetyNetAppsVerificationType": "none", // none, enabled
        "appActionIfAndroidSafetyNetAppsVerificationFailed": "block",
        "customBrowserPackageId": "com.microsoft.emmx", // Edge
        "customBrowserDisplayName": "Microsoft Edge",
        "minimumWipeOsVersion": null,
        "minimumWipeAppVersion": null,
        "appActionIfDeviceComplianceRequired": "block",
        "appActionIfMaximumPinRetriesExceeded": "block",
        "biometricAuthenticationBlocked": false,
        "blockAfterCompanyPortalUpdateDeferralInDays": 0,
        "warnAfterCompanyPortalUpdateDeferralInDays": 0,
        "exemptedAppPackages": []
    })
}

/// Android Email Profile (Exchange ActiveSync)
fn generate_android_email_profile(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileEasEmailProfileBase",
        "displayName": format!("{} - Android Email Profile", args.name),
        "description": "Corporate email configuration for Exchange Online",

        // Account
        "accountName": "Corporate Email",
        "hostName": "outlook.office365.com",
        "emailAddressSource": "primarySmtpAddress",
        "usernameSource": "primarySmtpAddress",
        "authenticationMethod": "usernameAndPassword",

        // Sync Settings
        "durationOfEmailToSync": "oneWeek",
        "emailSyncSchedule": "asMessagesArrive", // manual, fifteenMinutes, thirtyMinutes, sixtyMinutes, asMessagesArrive

        // SSL
        "requireSsl": true,

        // S/MIME (optional)
        "smimeSigningEnabled": false,
        "smimeEncryptionEnabled": false
    })
}

/// Android WiFi Profile (example)
fn generate_android_wifi_profile(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileWiFiConfiguration",
        "displayName": format!("{} - Corporate WiFi", args.name),
        "description": "Corporate wireless network configuration",

        // Network
        "networkName": "CorpWiFi",
        "ssid": "CorpWiFi",
        "connectAutomatically": true,
        "connectWhenNetworkNameIsHidden": false,

        // Security
        "wiFiSecurityType": "wpaEnterprise", // open, wep, wpaPersonal, wpaEnterprise

        // EAP Configuration (for wpaEnterprise)
        "eapType": "peap", // eapTls, leap, eapSim, eapTtls, peap, eapFast
        "innerAuthenticationProtocolForEapTtls": "microsoftChapVersionTwo", // unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo
        "outerIdentityPrivacyTemporaryValue": "anonymous@example.com",

        // Certificates (would reference deployed cert profiles)
        "rootCertificateForServerValidation": null,
        "identityCertificateForClientAuthentication": null,
        "trustedServerCertificateNames": []
    })
}

/// Android Microsoft Defender for Endpoint
fn generate_android_defender_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.androidManagedStoreApp",
        "displayName": format!("{} - Microsoft Defender for Endpoint (Android)", args.name),
        "description": "Microsoft Defender for Endpoint mobile threat defense",

        // App Info
        "publisher": "Microsoft Corporation",
        "appStoreUrl": "https://play.google.com/store/apps/details?id=com.microsoft.scmx",
        "packageId": "com.microsoft.scmx",

        // Installation
        "installAsManaged": true,
        "appAvailability": "requiredInstall", // availableInstall, requiredInstall, uninstall, availableWithoutEnrollment

        // Configuration (Managed App Config)
        "configuration": {
            "DefenderEnabled": true,
            "WebProtection": true,
            "NetworkProtection": true,
            "AutoOnboard": true,
            "VPN": false // Optional VPN-based protection
        }
    })
}

/// Generate basic Android baseline (lightweight)
pub fn generate_basic_android_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Basic Work Profile compliance
    policies.push(json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileCompliancePolicy",
        "displayName": format!("{} - Android Basic Compliance", args.name),
        "description": "Basic Android compliance requirements",
        "osMinimumVersion": "9.0",
        "passwordRequired": true,
        "passwordMinimumLength": 6,
        "securityBlockJailbrokenDevices": true,
        "storageRequireEncryption": true
    }));

    // Basic device restrictions
    policies.push(json!({
        "@odata.type": "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration",
        "displayName": format!("{} - Android Basic Restrictions", args.name),
        "description": "Basic Android device restrictions",
        "passwordRequiredType": "numeric",
        "passwordMinimumLength": 6,
        "workProfileDataSharingType": "preventAny"
    }));

    Ok(json!({
        "version": "1.0",
        "template": "android-basic",
        "platform": "Android",
        "metadata": {
            "description": "Basic Android management baseline",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &args.name
        },
        "policies": policies
    }))
}

/// App Package IDs for common enterprise apps on Android
pub mod app_ids {
    pub const OUTLOOK: &str = "com.microsoft.office.outlook";
    pub const TEAMS: &str = "com.microsoft.teams";
    pub const WORD: &str = "com.microsoft.office.word";
    pub const EXCEL: &str = "com.microsoft.office.excel";
    pub const POWERPOINT: &str = "com.microsoft.office.powerpoint";
    pub const ONEDRIVE: &str = "com.microsoft.skydrive";
    pub const SHAREPOINT: &str = "com.microsoft.sharepoint";
    pub const EDGE: &str = "com.microsoft.emmx";
    pub const ONENOTE: &str = "com.microsoft.office.onenote";
    pub const AUTHENTICATOR: &str = "com.azure.authenticator";
    pub const COMPANY_PORTAL: &str = "com.microsoft.windowsintune.companyportal";
    pub const DEFENDER: &str = "com.microsoft.scmx";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args(name: &str, defender: bool) -> NewArgs {
        NewArgs {
            platform: "android".to_string(),
            encryption: true,
            defender,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: name.to_string(),
            template: "basic".to_string(),
            autopilot_group_name: None,
            bitlocker_policy_name: None,
            update_ring_name: None,
            feature_update_version: None,
            no_bitlocker: false,
            no_updates: false,
            firewall_policy_name: None,
            no_firewall: false,
        }
    }

    #[test]
    fn test_generate_android_baseline_structure() {
        let args = create_test_args("Test Baseline", true);
        let baseline = generate_android_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "Android");
        assert_eq!(baseline["template"], "android-baseline");

        let policies = baseline["policies"].as_array().unwrap();
        // 7 base policies + 1 defender = 8
        assert_eq!(policies.len(), 8);
    }

    #[test]
    fn test_generate_android_baseline_without_defender() {
        let args = create_test_args("Test", false);
        let baseline = generate_android_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        // 7 base policies without defender
        assert_eq!(policies.len(), 7);
    }

    #[test]
    fn test_android_work_profile_compliance() {
        let args = create_test_args("Test", true);
        let policy = generate_android_work_profile_compliance(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidWorkProfileCompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("Android Work Profile Compliance")
        );
        assert_eq!(policy["osMinimumVersion"], "10.0");
        assert_eq!(policy["passwordRequired"], true);
        assert_eq!(policy["storageRequireEncryption"], true);
        assert_eq!(policy["securityBlockJailbrokenDevices"], true);
    }

    #[test]
    fn test_android_fully_managed_compliance() {
        let args = create_test_args("Test", false);
        let policy = generate_android_fully_managed_compliance(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidDeviceOwnerCompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("Fully Managed Compliance")
        );
        assert_eq!(policy["passwordMinimumLength"], 8);
        assert_eq!(
            policy["securityRequireSafetyNetAttestationCertifiedDevice"],
            true
        );
    }

    #[test]
    fn test_android_work_profile_restrictions() {
        let args = create_test_args("Test", false);
        let policy = generate_android_work_profile_restrictions(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidWorkProfileGeneralDeviceConfiguration"
        );
        assert_eq!(policy["workProfileDataSharingType"], "preventAny");
        assert_eq!(policy["workProfileBlockCrossProfileCopyPaste"], true);
        assert_eq!(policy["securityRequireVerifyApps"], true);
    }

    #[test]
    fn test_android_fully_managed_restrictions() {
        let args = create_test_args("Test", false);
        let policy = generate_android_fully_managed_restrictions(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidDeviceOwnerGeneralDeviceConfiguration"
        );
        assert_eq!(policy["appsBlockInstallFromUnknownSources"], true);
        assert_eq!(policy["usbDebuggingBlocked"], true);
        assert_eq!(policy["factoryResetBlocked"], true);
    }

    #[test]
    fn test_android_app_protection_policy() {
        let args = create_test_args("Test", false);
        let policy = generate_android_app_protection_policy(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidManagedAppProtection"
        );
        assert!(policy["apps"].is_array());
        let apps = policy["apps"].as_array().unwrap();
        assert!(!apps.is_empty());
        assert_eq!(policy["pinRequired"], true);
        assert_eq!(policy["encryptAppData"], true);
        assert_eq!(policy["dataBackupBlocked"], true);
    }

    #[test]
    fn test_android_email_profile() {
        let args = create_test_args("Test", false);
        let policy = generate_android_email_profile(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidWorkProfileEasEmailProfileBase"
        );
        assert_eq!(policy["hostName"], "outlook.office365.com");
        assert_eq!(policy["requireSsl"], true);
    }

    #[test]
    fn test_android_wifi_profile() {
        let args = create_test_args("Test", false);
        let policy = generate_android_wifi_profile(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidWorkProfileWiFiConfiguration"
        );
        assert_eq!(policy["wiFiSecurityType"], "wpaEnterprise");
        assert_eq!(policy["connectAutomatically"], true);
    }

    #[test]
    fn test_android_defender_policy() {
        let args = create_test_args("Test", true);
        let policy = generate_android_defender_policy(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.androidManagedStoreApp"
        );
        assert_eq!(policy["packageId"], "com.microsoft.scmx");
        assert!(
            policy["configuration"]["DefenderEnabled"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn test_generate_basic_android_baseline() {
        let args = create_test_args("Basic Test", false);
        let baseline = generate_basic_android_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "Android");
        assert_eq!(baseline["template"], "android-basic");

        let policies = baseline["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2); // Compliance + Restrictions
    }

    #[test]
    fn test_android_compliance_with_custom_min_os() {
        let args = NewArgs {
            platform: "android".to_string(),
            encryption: true,
            defender: false,
            min_os: Some("13.0".to_string()),
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
        let policy = generate_android_work_profile_compliance(&args);

        assert_eq!(policy["osMinimumVersion"], "13.0");
    }

    #[test]
    fn test_app_ids_constants() {
        assert_eq!(app_ids::OUTLOOK, "com.microsoft.office.outlook");
        assert_eq!(app_ids::TEAMS, "com.microsoft.teams");
        assert_eq!(app_ids::DEFENDER, "com.microsoft.scmx");
        assert_eq!(app_ids::EDGE, "com.microsoft.emmx");
    }
}
