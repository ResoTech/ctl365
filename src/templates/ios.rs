//! iOS/iPadOS Baseline Configuration
//!
//! Comprehensive iOS device management including:
//! - Compliance policies (OS version, jailbreak detection, encryption)
//! - Device restrictions (passcode, features, security)
//! - App protection policies (MAM without enrollment)
//! - Email/VPN/WiFi profiles
//!
//! Based on OpenIntuneBaseline and Apple Platform Deployment best practices

#![allow(dead_code)]

use crate::cmd::baseline::NewArgs;
use crate::error::Result;
use serde_json::{Value, json};

/// Generate iOS baseline with compliance + configuration + app protection
pub fn generate_ios_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Compliance Policies
    policies.push(generate_ios_compliance_policy(args));

    // Device Configuration Policies
    policies.push(generate_ios_device_restrictions(args));
    policies.push(generate_ios_passcode_policy(args));
    policies.push(generate_ios_email_profile(args));

    // App Protection Policies (MAM)
    policies.push(generate_ios_app_protection_policy(args));

    // Conditional settings based on flags
    if args.defender {
        policies.push(generate_ios_defender_policy(args));
    }

    Ok(json!({
        "version": "1.0",
        "template": "ios-baseline",
        "platform": "iOS",
        "metadata": {
            "description": "iOS/iPadOS enterprise management baseline",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &args.name,
            "policies_count": policies.len()
        },
        "policies": policies
    }))
}

/// iOS Compliance Policy - Device health and security requirements
fn generate_ios_compliance_policy(args: &NewArgs) -> Value {
    let min_os = args.min_os.as_deref().unwrap_or("17.0"); // iOS 17+

    json!({
        "@odata.type": "#microsoft.graph.iosCompliancePolicy",
        "displayName": format!("{} - iOS Compliance Policy", args.name),
        "description": "iOS device compliance requirements for conditional access",

        // OS Version
        "osMinimumVersion": min_os,
        "osMaximumVersion": null,

        // Security
        "passcodeRequired": true,
        "passcodeMinimumLength": 6,
        "passcodeMinimumCharacterSetCount": null,
        "passcodeRequiredType": "numeric", // numeric, alphanumeric
        "passcodeMinutesOfInactivityBeforeLock": 5,
        "passcodeExpirationDays": null,
        "passcodePreviousPasscodeBlockCount": 5,

        // Device Security
        "securityBlockJailbrokenDevices": true,
        "deviceThreatProtectionEnabled": args.defender,
        "deviceThreatProtectionRequiredSecurityLevel": "medium", // low, medium, high, secured

        // Encryption
        "storageRequireEncryption": true,

        // Managed Email Profile
        "managedEmailProfileRequired": false, // Set true if deploying email profile

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

/// iOS Device Restrictions - Feature and security controls
fn generate_ios_device_restrictions(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration",
        "displayName": format!("{} - iOS Device Restrictions", args.name),
        "description": "iOS feature restrictions and security controls",

        // General
        "accountBlockModification": false,
        "activationLockAllowWhenSupervised": true,
        "airDropBlocked": false,
        "airDropForceUnmanagedDropTarget": true, // Prevent AirDrop to non-managed devices
        "airPlayForcePairingPasswordForOutgoingRequests": true,
        "appleWatchBlockPairing": false,
        "appleNewsBlocked": false,

        // App Store
        "appStoreBlockAutomaticDownloads": false,
        "appStoreBlocked": false,
        "appStoreBlockInAppPurchases": false,
        "appStoreBlockUIAppInstallation": false,
        "appStoreRequirePassword": true,

        // Apps
        "appRemovalBlocked": false,
        "appsAllowList": [], // Whitelist specific apps
        "appsVisibilityList": [], // Hide specific apps
        "appsVisibilityListType": "none", // none, appsInListCompliant, appsNotInListCompliant

        // iCloud
        "iCloudBlockBackup": false,
        "iCloudBlockDocumentSync": false,
        "iCloudBlockPhotoStreamSync": false,
        "iCloudRequireEncryptedBackup": true,

        // Security
        "passcodeBlockSimple": true, // No simple passcodes (1234, etc.)
        "passcodeRequired": true,
        "passcodeMinimumLength": 6,
        "passcodeRequiredType": "numeric",
        "passcodeMinutesOfInactivityBeforeLock": 5,
        "passcodeMinutesOfInactivityBeforeScreenTimeout": 5,
        "passcodePreviousPasscodeBlockCount": 5,
        "passcodeSignInFailureCountBeforeWipe": 11, // Wipe after 11 failed attempts

        // Lock Screen
        "lockScreenBlockControlCenter": false,
        "lockScreenBlockNotificationView": false,
        "lockScreenBlockPassbook": false,
        "lockScreenBlockTodayView": false,

        // Network
        "cellularBlockDataRoaming": false,
        "cellularBlockVoiceRoaming": false,
        "cellularBlockPersonalHotspot": false,

        // Safari
        "safariBlockAutofill": false,
        "safariBlockJavaScript": false,
        "safariBlockPopups": true,
        "safariRequireFraudWarning": true,
        "safariAcceptCookies": "allowFromWebsitesVisited", // blockAll, allowFromWebsitesVisited, allowFromAllWebsites

        // Siri
        "siriBlocked": false,
        "siriBlockedWhenLocked": true,
        "siriBlockUserGeneratedContent": false,
        "siriRequireProfanityFilter": true,

        // Game Center
        "gameCenterBlocked": false,
        "gamePlayerFriendsBlocked": false,

        // Media
        "mediaContentRatingApps": "allAllowed", // allAllowed, allBlocked, agesAbove4, etc.

        // Other
        "diagnosticDataBlockSubmission": false,
        "screenCaptureBlocked": false,
        "enterpriseAppBlockTrust": false,
        "enterpriseAppBlockTrustModification": false
    })
}

/// iOS Passcode Policy - Enhanced password requirements
fn generate_ios_passcode_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration",
        "displayName": format!("{} - iOS Passcode Policy", args.name),
        "description": "Strong passcode requirements for iOS devices",

        "passcodeRequired": true,
        "passcodeBlockSimple": true,
        "passcodeMinimumLength": 8,
        "passcodeRequiredType": "alphanumeric", // numeric, alphanumeric
        "passcodeMinimumCharacterSetCount": 3, // Require 3 of: lowercase, uppercase, number, symbol
        "passcodeMinutesOfInactivityBeforeLock": 2,
        "passcodeMinutesOfInactivityBeforeScreenTimeout": 2,
        "passcodeExpirationDays": 365,
        "passcodePreviousPasscodeBlockCount": 5,
        "passcodeSignInFailureCountBeforeWipe": 11,

        // Touch ID / Face ID
        "touchIdTimeoutInHours": 48, // Require passcode after 48 hours
        "passcodeBlockFingerprintUnlock": false,
        "passcodeBlockFingerprintModification": false
    })
}

/// iOS Email Profile - Corporate email configuration
fn generate_ios_email_profile(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.iosEasEmailProfileConfiguration",
        "displayName": format!("{} - iOS Email Profile", args.name),
        "description": "Corporate email configuration for Exchange Online",

        // Account
        "accountName": "Corporate Email",
        "hostName": "outlook.office365.com",
        "emailAddressSource": "primarySmtpAddress",
        "usernameSource": "primarySmtpAddress",

        // Authentication
        "authenticationMethod": "usernameAndPassword", // usernameAndPassword, certificate, derivedCredential
        "blockMovingMessagesToOtherEmailAccounts": true,
        "blockSendingEmailFromThirdPartyApps": false,
        "blockSyncingRecentlyUsedEmailAddresses": false,

        // S/MIME
        "smimeEnablePerMessageSwitch": false,
        "smimeEncryptByDefaultEnabled": false,
        "smimeSigningEnabled": false,

        // Sync Settings
        "durationOfEmailToSync": "oneWeek", // oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited
        "easServices": "mail, contacts, calendars, reminders, notes",
        "easServicesUserOverrideEnabled": false,

        // SSL
        "requireSsl": true,
        "requireSmime": false,
        "useOAuth": true
    })
}

/// iOS App Protection Policy (MAM) - Mobile Application Management without enrollment
fn generate_ios_app_protection_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.iosManagedAppProtection",
        "displayName": format!("{} - iOS App Protection Policy", args.name),
        "description": "App protection policy (MAM) for managed apps on iOS",

        // Apps covered
        "apps": [
            {
                "id": "com.microsoft.office.outlook.ios",
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
            }
        ],

        // Assignment
        "assignments": [],

        // Data Protection
        "dataBackupBlocked": true, // Block backup to iCloud
        "deviceComplianceRequired": true,
        "managedBrowserToOpenLinksRequired": true, // Open links in Edge
        "saveAsBlocked": false,
        "periodOfflineBeforeAccessCheck": "PT12H", // 12 hours offline before check
        "periodOnlineBeforeAccessCheck": "PT30M", // 30 minutes online before check
        "allowedInboundDataTransferSources": "managedApps", // allApps, managedApps, none
        "allowedOutboundClipboardSharingLevel": "managedAppsWithPasteIn", // blocked, managedApps, managedAppsWithPasteIn, allApps
        "allowedOutboundDataTransferDestinations": "managedApps", // allApps, managedApps, none
        "organizationalCredentialsRequired": false,
        "contactSyncBlocked": false,
        "printBlocked": false,
        "fingerprintBlocked": false, // Allow Face ID / Touch ID

        // Encryption
        "appDataEncryptionType": "whenDeviceLocked", // whenDeviceLocked, afterDeviceRestart, useDeviceSettings

        // Access Requirements
        "pinRequired": true,
        "pinCharacterSet": "alphanumericAndSymbol", // numeric, alphanumericAndSymbol
        "minimumPinLength": 6,
        "maximumPinRetries": 5,
        "simplePinBlocked": true,
        "minimumRequiredOsVersion": "17.0",
        "minimumWarningOsVersion": "17.0",
        "minimumRequiredAppVersion": null,
        "minimumWarningAppVersion": null,
        "managedBrowser": "microsoftEdge", // microsoftEdge, notConfigured

        // Conditional Launch
        "periodOfflineBeforeWipeIsEnforced": "P90D", // 90 days offline then wipe
        "periodBeforePinReset": "P0D", // Never reset PIN automatically

        // iOS-specific
        "appActionIfIosDeviceModelNotAllowed": "block", // block, wipe
        "appDataEncryptionType": "whenDeviceLocked",
        "minimumRequiredSdkVersion": null,
        "deployedAppCount": 7,
        "faceIdBlocked": false,
        "minimumWipeSdkVersion": null,
        "allowedIosDeviceModels": [], // Empty = all models allowed
        "appActionIfIosDeviceModelNotAllowed": "block",
        "thirdPartyKeyboardsBlocked": false,
        "filterOpenInToOnlyManagedApps": true
    })
}

/// iOS Microsoft Defender for Endpoint
fn generate_ios_defender_policy(args: &NewArgs) -> Value {
    json!({
        "@odata.type": "#microsoft.graph.iosLobApp",
        "displayName": format!("{} - Microsoft Defender for Endpoint (iOS)", args.name),
        "description": "Microsoft Defender for Endpoint mobile threat defense",

        // App Info
        "publisher": "Microsoft Corporation",
        "bundleId": "com.microsoft.scmx",
        "applicableDeviceType": {
            "iPad": true,
            "iPhoneAndIPod": true
        },
        "minimumSupportedOperatingSystem": {
            "v17_0": true
        },

        // Installation
        "installAsManaged": true,

        // Configuration
        "notes": "Mobile threat defense and web protection for iOS devices",

        // App Configuration (Managed App Config)
        "configuration": {
            "DefenderEnabled": true,
            "WebProtection": true,
            "NetworkProtection": true,
            "AutoOnboard": true
        }
    })
}

/// Generate basic iOS baseline (lightweight)
pub fn generate_basic_ios_baseline(args: &NewArgs) -> Result<Value> {
    let mut policies = Vec::new();

    // Basic compliance only
    policies.push(json!({
        "@odata.type": "#microsoft.graph.iosCompliancePolicy",
        "displayName": format!("{} - iOS Basic Compliance", args.name),
        "description": "Basic iOS compliance requirements",
        "osMinimumVersion": "16.0",
        "passcodeRequired": true,
        "passcodeMinimumLength": 6,
        "securityBlockJailbrokenDevices": true,
        "storageRequireEncryption": true
    }));

    // Basic device restrictions
    policies.push(json!({
        "@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration",
        "displayName": format!("{} - iOS Basic Restrictions", args.name),
        "description": "Basic iOS device restrictions",
        "passcodeRequired": true,
        "passcodeMinimumLength": 6,
        "passcodeBlockSimple": true
    }));

    Ok(json!({
        "version": "1.0",
        "template": "ios-basic",
        "platform": "iOS",
        "metadata": {
            "description": "Basic iOS management baseline",
            "source": "ctl365",
            "generated": chrono::Utc::now().to_rfc3339(),
            "name": &args.name
        },
        "policies": policies
    }))
}

/// App IDs for common enterprise apps on iOS
pub mod app_ids {
    pub const OUTLOOK: &str = "com.microsoft.office.outlook.ios";
    pub const TEAMS: &str = "com.microsoft.teams";
    pub const WORD: &str = "com.microsoft.office.word";
    pub const EXCEL: &str = "com.microsoft.office.excel";
    pub const POWERPOINT: &str = "com.microsoft.office.powerpoint";
    pub const ONEDRIVE: &str = "com.microsoft.skydrive";
    pub const SHAREPOINT: &str = "com.microsoft.sharepoint";
    pub const EDGE: &str = "com.microsoft.msedge";
    pub const ONENOTE: &str = "com.microsoft.onenote";
    pub const AUTHENTICATOR: &str = "com.azure.authenticator";
    pub const COMPANY_PORTAL: &str = "com.microsoft.intunecompanyportal";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args(name: &str, defender: bool) -> NewArgs {
        NewArgs {
            platform: "ios".to_string(),
            encryption: true,
            defender,
            min_os: None,
            mde_onboarding: None,
            output: None,
            name: name.to_string(),
            template: "basic".to_string(),
        }
    }

    #[test]
    fn test_generate_ios_baseline_structure() {
        let args = create_test_args("Test", false);
        let baseline = generate_ios_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "iOS");
        assert_eq!(baseline["template"], "ios-baseline");
        assert!(baseline["policies"].is_array());
    }

    #[test]
    fn test_generate_ios_baseline_with_defender() {
        let args = create_test_args("Test", true);
        let baseline = generate_ios_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        let defender_policy = policies.iter().find(|p| {
            p["displayName"]
                .as_str()
                .map(|n| n.contains("Defender"))
                .unwrap_or(false)
        });
        assert!(defender_policy.is_some());
    }

    #[test]
    fn test_generate_ios_baseline_without_defender() {
        let args = create_test_args("Test", false);
        let baseline = generate_ios_baseline(&args).unwrap();

        let policies = baseline["policies"].as_array().unwrap();
        let defender_policy = policies.iter().find(|p| {
            p["displayName"]
                .as_str()
                .map(|n| n.contains("Defender"))
                .unwrap_or(false)
        });
        assert!(defender_policy.is_none());
    }

    #[test]
    fn test_ios_compliance_policy() {
        let args = create_test_args("Test", true);
        let policy = generate_ios_compliance_policy(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.iosCompliancePolicy"
        );
        assert!(
            policy["displayName"]
                .as_str()
                .unwrap()
                .contains("iOS Compliance")
        );
        assert_eq!(policy["osMinimumVersion"], "17.0");
        assert_eq!(policy["securityBlockJailbrokenDevices"], true);
        assert_eq!(policy["passcodeRequired"], true);
    }

    #[test]
    fn test_ios_device_restrictions() {
        let args = create_test_args("Test", false);
        let policy = generate_ios_device_restrictions(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.iosGeneralDeviceConfiguration"
        );
        assert_eq!(policy["passcodeBlockSimple"], true);
        assert_eq!(policy["iCloudRequireEncryptedBackup"], true);
        assert_eq!(policy["safariBlockPopups"], true);
    }

    #[test]
    fn test_ios_app_protection_policy() {
        let args = create_test_args("Test", false);
        let policy = generate_ios_app_protection_policy(&args);

        assert_eq!(
            policy["@odata.type"],
            "#microsoft.graph.iosManagedAppProtection"
        );
        assert!(policy["apps"].is_array());
        let apps = policy["apps"].as_array().unwrap();
        assert!(!apps.is_empty());
        assert_eq!(policy["pinRequired"], true);
        assert_eq!(policy["dataBackupBlocked"], true);
    }

    #[test]
    fn test_generate_basic_ios_baseline() {
        let args = create_test_args("Basic Test", false);
        let baseline = generate_basic_ios_baseline(&args).unwrap();

        assert_eq!(baseline["version"], "1.0");
        assert_eq!(baseline["platform"], "iOS");
        assert_eq!(baseline["template"], "ios-basic");

        let policies = baseline["policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2); // Compliance + Restrictions
    }

    #[test]
    fn test_ios_compliance_with_custom_min_os() {
        let args = NewArgs {
            platform: "ios".to_string(),
            encryption: true,
            defender: false,
            min_os: Some("18.0".to_string()),
            mde_onboarding: None,
            output: None,
            name: "Test".to_string(),
            template: "basic".to_string(),
        };
        let policy = generate_ios_compliance_policy(&args);

        assert_eq!(policy["osMinimumVersion"], "18.0");
    }
}
