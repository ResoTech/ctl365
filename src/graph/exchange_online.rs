//! Exchange Online Management
//!
//! Handles tenant-wide Exchange Online configuration including:
//! - Archive mailbox enablement
//! - Retention and archive policies
//! - Quarantine notification settings
//! - Anti-spam configuration

#![allow(dead_code)]

use crate::error::Result;
use crate::graph::GraphClient;
use serde_json::{Value, json};

/// Enable archive mailbox for all users tenant-wide
pub async fn enable_archive_mailbox_tenant_wide(client: &GraphClient) -> Result<Value> {
    // Get all users with mailboxes
    let users: Value = client
        .get("users?$filter=assignedLicenses/any(x:x ne null)&$select=id,userPrincipalName,mail")
        .await?;

    let mut results = Vec::new();

    if let Some(user_list) = users["value"].as_array() {
        for user in user_list {
            if let Some(upn) = user["userPrincipalName"].as_str() {
                match enable_user_archive_mailbox(client, upn).await {
                    Ok(result) => results.push(json!({
                        "userPrincipalName": upn,
                        "status": "success",
                        "result": result
                    })),
                    Err(e) => results.push(json!({
                        "userPrincipalName": upn,
                        "status": "error",
                        "error": e.to_string()
                    })),
                }
            }
        }
    }

    Ok(json!({
        "totalUsers": results.len(),
        "results": results
    }))
}

/// Enable archive mailbox for a specific user
pub async fn enable_user_archive_mailbox(
    client: &GraphClient,
    user_principal_name: &str,
) -> Result<Value> {
    // Exchange Online uses PowerShell cmdlets via Graph API
    // Enable-Mailbox -Identity <UPN> -Archive

    let payload = json!({
        "@odata.type": "#microsoft.graph.mailboxSettings",
        "archiveEnabled": true
    });

    client
        .patch(
            &format!("users/{}/mailboxSettings", user_principal_name),
            &payload,
        )
        .await
}

/// Configure retention policy for archive after specified years
/// Default: Move emails to archive after 3 years
pub async fn configure_retention_policy(
    client: &GraphClient,
    policy_name: &str,
    retain_years: u32,
) -> Result<Value> {
    // Create or update retention policy
    // Exchange retention tags: MoveToArchive after X years

    let retention_days = retain_years * 365;

    let policy = json!({
        "@odata.type": "#microsoft.graph.retentionLabel",
        "displayName": policy_name,
        "behaviorDuringRetentionPeriod": "doNotRetain",
        "actionAfterRetentionPeriod": "moveToArchive",
        "retentionDuration": {
            "@odata.type": "#microsoft.graph.retentionDuration",
            "duration": format!("P{}D", retention_days)
        },
        "defaultRecordBehavior": "startLocked",
        "descriptionForAdmins": format!("Archive emails after {} years", retain_years),
        "descriptionForUsers": format!("Emails will be moved to your archive mailbox after {} years", retain_years)
    });

    // POST to create retention label
    client
        .post("security/labels/retentionLabels", &policy)
        .await
}

/// Apply retention policy to all mailboxes
pub async fn apply_retention_policy_tenant_wide(
    client: &GraphClient,
    policy_id: &str,
) -> Result<Value> {
    // Create retention label policy to auto-apply
    let policy = json!({
        "@odata.type": "#microsoft.graph.retentionLabelPolicy",
        "displayName": "Tenant-wide Archive Policy",
        "retentionLabelIds": [policy_id],
        "mode": "enforce",
        "locations": {
            "exchangeLocations": {
                "includeAll": true
            }
        }
    });

    client
        .post("security/labels/retentionLabelPolicies", &policy)
        .await
}

/// Disable quarantine email notifications for end users
pub async fn disable_quarantine_notifications(client: &GraphClient) -> Result<Value> {
    // Update quarantine policy to disable end-user notifications

    let policy = json!({
        "@odata.type": "#microsoft.graph.quarantinePolicy",
        "endUserSpamNotificationFrequency": 0, // Disable notifications
        "endUserSpamNotificationEnabled": false,
        "endUserQuarantinePermissionsValue": 0 // No permissions to release
    });

    // Update default quarantine policy
    client
        .patch("security/threatIntelligence/quarantinePolicy", &policy)
        .await
}

/// Configure anti-spam policy with recommended settings
pub async fn configure_antispam_policy(client: &GraphClient, policy_name: &str) -> Result<Value> {
    // Create or update anti-spam (hosted content filter) policy

    let policy = json!({
        "@odata.type": "#microsoft.graph.hostedContentFilterPolicy",
        "name": policy_name,
        "spamAction": "moveToJmf", // Move to Junk Mail folder
        "highConfidenceSpamAction": "quarantine",
        "phishSpamAction": "quarantine",
        "highConfidencePhishAction": "quarantine",
        "bulkSpamAction": "moveToJmf",
        "bulkThreshold": 6,
        "markAsSpamBulkMail": "on",
        "markAsSpamFramedFromDifferentDomains": "on",
        "markAsSpamNdrBackscatter": "on",
        "markAsSpamSpfRecordHardFail": "on",
        "markAsSpamFromAddressAuthFail": "on",
        "markAsSpamEmptyMessages": "on",
        "markAsSpamJavaScriptInHtml": "on",
        "markAsSpamEmbedTagsInHtml": "on",
        "increaseSCLWithImageLinks": "on",
        "increaseSCLWithNumericIps": "on",
        "increaseSCLWithRedirectToOtherPort": "on",
        "increaseSCLWithBizOrInfoUrls": "on",
        "markAsSpamWebBugsInHtml": "on",
        "markAsSpamSensitiveWordList": "on",
        "enableEndUserSpamNotifications": false,
        "endUserSpamNotificationFrequency": 0,
        "enableLanguageBlockList": false,
        "enableRegionBlockList": false,
        "allowedSenders": [],
        "allowedSenderDomains": [],
        "blockedSenders": [],
        "blockedSenderDomains": []
    });

    client
        .post(
            "security/threatIntelligence/hostedContentFilterPolicies",
            &policy,
        )
        .await
}

/// Get current anti-spam policies
pub async fn list_antispam_policies(client: &GraphClient) -> Result<Value> {
    client
        .get("security/threatIntelligence/hostedContentFilterPolicies")
        .await
}

/// Configure anti-malware policy
pub async fn configure_antimalware_policy(
    client: &GraphClient,
    policy_name: &str,
) -> Result<Value> {
    let policy = json!({
        "@odata.type": "#microsoft.graph.malwareFilterPolicy",
        "name": policy_name,
        "enableFileFilter": true,
        "enableInternalSenderNotifications": false,
        "enableExternalSenderNotifications": false,
        "enableInternalSenderAdminNotifications": true,
        "enableExternalSenderAdminNotifications": true,
        "fileTypes": [
            "ace", "ani", "app", "cab", "dll", "exe", "jar", "reg", "scr", "vbe", "vbs"
        ],
        "zap": {
            "enabled": true
        },
        "commonAttachmentFilter": {
            "enabled": true
        }
    });

    client
        .post("security/threatIntelligence/malwareFilterPolicies", &policy)
        .await
}

/// Configure outbound spam filter policy
pub async fn configure_outbound_spam_policy(client: &GraphClient) -> Result<Value> {
    let policy = json!({
        "@odata.type": "#microsoft.graph.outboundSpamFilterPolicy",
        "notifyOutboundSpam": true,
        "notifyOutboundSpamRecipients": [],
        "recipientLimitExternalPerHour": 500,
        "recipientLimitInternalPerHour": 1000,
        "recipientLimitPerDay": 1000,
        "actionWhenThresholdReached": "blockUser", // Block account when limit reached
        "autoForwardingMode": "off" // Prevent auto-forwarding to external domains
    });

    client
        .patch(
            "security/threatIntelligence/outboundSpamFilterPolicy",
            &policy,
        )
        .await
}

/// Configure Safe Links policy (Defender for Office 365)
pub async fn configure_safe_links_policy(client: &GraphClient, policy_name: &str) -> Result<Value> {
    let policy = json!({
        "@odata.type": "#microsoft.graph.safeLinkPolicy",
        "name": policy_name,
        "isEnabled": true,
        "scanUrls": true,
        "enableForInternalSenders": true,
        "deliverMessageAfterScan": true,
        "disableUrlRewrite": false,
        "trackClicks": true,
        "enableSafeLinksForEmail": true,
        "enableSafeLinksForTeams": true,
        "enableSafeLinksForOffice": true,
        "doNotRewriteUrls": []
    });

    client
        .post("security/threatIntelligence/safeLinkPolicies", &policy)
        .await
}

/// Configure Safe Attachments policy (Defender for Office 365)
pub async fn configure_safe_attachments_policy(
    client: &GraphClient,
    policy_name: &str,
) -> Result<Value> {
    let policy = json!({
        "@odata.type": "#microsoft.graph.safeAttachmentPolicy",
        "name": policy_name,
        "isEnabled": true,
        "action": "dynamicDelivery", // Deliver message while scanning attachments
        "redirect": false,
        "actionOnError": true, // Apply action even if scanning errors occur
        "enableForInternalSenders": true
    });

    client
        .post(
            "security/threatIntelligence/safeAttachmentPolicies",
            &policy,
        )
        .await
}

/// Get Exchange Online organization config
pub async fn get_organization_config(client: &GraphClient) -> Result<Value> {
    client.get("organization").await
}

/// Configure tenant-wide transport rules (mail flow rules)
pub async fn create_transport_rule(
    client: &GraphClient,
    rule_name: &str,
    rule_config: &Value,
) -> Result<Value> {
    let rule = json!({
        "@odata.type": "#microsoft.graph.transportRule",
        "name": rule_name,
        "enabled": true,
        "mode": "enforce",
        "priority": 0,
        "conditions": rule_config["conditions"],
        "actions": rule_config["actions"]
    });

    client
        .post("security/threatIntelligence/transportRules", &rule)
        .await
}
