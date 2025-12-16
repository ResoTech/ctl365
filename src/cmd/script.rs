//! Platform Scripts Deployment
//!
//! Deploy PowerShell scripts to Windows devices via Intune:
//! - Remediation scripts (detection + remediation pairs)
//! - Platform scripts (single scripts)
//! - Proactive remediations
//!
//! Based on shell-intune-samples patterns

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use clap::Args;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct DeployScriptArgs {
    /// Path to the script file (.ps1 or .sh)
    #[arg(short, long)]
    pub file: PathBuf,

    /// Script name (defaults to filename)
    #[arg(long)]
    pub name: Option<String>,

    /// Script description
    #[arg(long)]
    pub description: Option<String>,

    /// Platform: windows, macos, linux
    #[arg(short, long, default_value = "windows")]
    pub platform: String,

    /// Run as 32-bit process on 64-bit systems
    #[arg(long)]
    pub run_as_32bit: bool,

    /// Run script using logged-on credentials (user context)
    #[arg(long)]
    pub run_as_user: bool,

    /// Enforce script signature check
    #[arg(long)]
    pub enforce_signature: bool,

    /// Assignment group ID (optional)
    #[arg(long)]
    pub group_id: Option<String>,

    /// Dry run - show what would be deployed
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct DeployRemediationArgs {
    /// Path to detection script (.ps1)
    #[arg(long)]
    pub detection: PathBuf,

    /// Path to remediation script (.ps1)
    #[arg(long)]
    pub remediation: PathBuf,

    /// Remediation name
    #[arg(long)]
    pub name: String,

    /// Description
    #[arg(long)]
    pub description: Option<String>,

    /// Publisher name
    #[arg(long)]
    pub publisher: Option<String>,

    /// Run detection script as 32-bit
    #[arg(long)]
    pub run_as_32bit: bool,

    /// Run scripts in user context
    #[arg(long)]
    pub run_as_user: bool,

    /// Schedule: once, hourly, daily
    #[arg(long, default_value = "daily")]
    pub schedule: String,

    /// Assignment group ID
    #[arg(long)]
    pub group_id: Option<String>,

    /// Dry run
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct ListScriptsArgs {
    /// Platform filter: windows, macos, linux, all
    #[arg(short, long, default_value = "all")]
    pub platform: String,

    /// Show verbose details
    #[arg(short = 'd', long = "detailed")]
    pub detailed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScriptMetadata {
    pub name: String,
    pub description: String,
    pub platform: String,
    pub script_content: String,
    pub run_as_account: String,
    pub enforce_signature_check: bool,
    pub run_as_32bit: bool,
}

/// Deploy a platform script to Intune
pub async fn deploy_script(args: DeployScriptArgs) -> Result<()> {
    println!("{} platform script...", "Deploying".cyan().bold());

    if !args.file.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "Script file does not exist: {}",
            args.file.display()
        )));
    }

    let script_content = fs::read_to_string(&args.file)?;
    let script_name = args.name.clone().unwrap_or_else(|| {
        args.file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Script")
            .to_string()
    });

    println!("→ Script: {}", script_name.cyan());
    println!("→ Platform: {}", args.platform.cyan());
    println!("→ File: {}", args.file.display().to_string().cyan());
    println!(
        "→ Run as: {}",
        if args.run_as_user { "User" } else { "System" }.cyan()
    );

    if args.dry_run {
        println!(
            "\n{} DRY RUN - Script would be deployed:",
            "ℹ".yellow().bold()
        );
        println!("  Name: {}", script_name);
        println!("  Platform: {}", args.platform);
        println!("  Lines: {}", script_content.lines().count());
        println!("  Size: {} bytes", script_content.len());
        return Ok(());
    }

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Encode script content as base64
    let encoded_content = base64_encode(&script_content);

    match args.platform.as_str() {
        "windows" => deploy_windows_script(&graph, &script_name, &args, &encoded_content).await?,
        "macos" => deploy_macos_script(&graph, &script_name, &args, &encoded_content).await?,
        "linux" => deploy_linux_script(&graph, &script_name, &args, &encoded_content).await?,
        _ => {
            return Err(crate::error::Ctl365Error::ConfigError(format!(
                "Unknown platform: {}. Valid: windows, macos, linux",
                args.platform
            )));
        }
    }

    println!("\n{} Script deployed successfully!", "✓".green().bold());

    Ok(())
}

/// Deploy a proactive remediation (detection + remediation pair)
pub async fn deploy_remediation(args: DeployRemediationArgs) -> Result<()> {
    println!("{} proactive remediation...", "Deploying".cyan().bold());

    if !args.detection.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "Detection script does not exist: {}",
            args.detection.display()
        )));
    }
    if !args.remediation.exists() {
        return Err(crate::error::Ctl365Error::ConfigError(format!(
            "Remediation script does not exist: {}",
            args.remediation.display()
        )));
    }

    let detection_content = fs::read_to_string(&args.detection)?;
    let remediation_content = fs::read_to_string(&args.remediation)?;

    println!("→ Name: {}", args.name.cyan());
    println!(
        "→ Detection: {}",
        args.detection.display().to_string().cyan()
    );
    println!(
        "→ Remediation: {}",
        args.remediation.display().to_string().cyan()
    );
    println!("→ Schedule: {}", args.schedule.cyan());

    if args.dry_run {
        println!(
            "\n{} DRY RUN - Remediation would be deployed:",
            "ℹ".yellow().bold()
        );
        println!("  Name: {}", args.name);
        println!("  Detection lines: {}", detection_content.lines().count());
        println!(
            "  Remediation lines: {}",
            remediation_content.lines().count()
        );
        return Ok(());
    }

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Encode scripts
    let detection_encoded = base64_encode(&detection_content);
    let remediation_encoded = base64_encode(&remediation_content);

    // Create the device health script (proactive remediation)
    let script_body = json!({
        "@odata.type": "#microsoft.graph.deviceHealthScript",
        "displayName": args.name,
        "description": args.description.clone().unwrap_or_else(|| "Deployed via ctl365".to_string()),
        "publisher": args.publisher.clone().unwrap_or_else(|| "IT Department".to_string()),
        "runAsAccount": if args.run_as_user { "user" } else { "system" },
        "enforceSignatureCheck": false,
        "runAs32Bit": args.run_as_32bit,
        "detectionScriptContent": detection_encoded,
        "remediationScriptContent": remediation_encoded,
        "roleScopeTagIds": []
    });

    println!("\n{} Creating proactive remediation...", "→".cyan());

    match graph
        .post_beta::<Value, Value>("deviceManagement/deviceHealthScripts", &script_body)
        .await
    {
        Ok(response) => {
            let script_id = response["id"].as_str().unwrap_or("unknown");
            println!("  {} Remediation created: {}", "✓".green(), script_id);

            // Assign to group if specified
            if let Some(group_id) = &args.group_id {
                assign_remediation_to_group(&graph, script_id, group_id).await?;
            }
        }
        Err(e) => {
            println!("  {} Failed: {}", "✗".red(), e);
        }
    }

    println!("\n{} Proactive remediation deployed!", "✓".green().bold());

    Ok(())
}

/// List deployed scripts
pub async fn list_scripts(args: ListScriptsArgs) -> Result<()> {
    println!("{} platform scripts...", "Listing".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", active_tenant.name.cyan().bold());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // List Windows PowerShell scripts
    if args.platform == "all" || args.platform == "windows" {
        println!("\n{} Windows PowerShell Scripts:", "→".cyan().bold());

        match graph
            .get_beta::<Value>("deviceManagement/deviceManagementScripts")
            .await
        {
            Ok(response) => {
                if let Some(scripts) = response["value"].as_array() {
                    if scripts.is_empty() {
                        println!("  No Windows scripts found");
                    } else {
                        for script in scripts {
                            let name = script["displayName"].as_str().unwrap_or("Unknown");
                            let id = script["id"].as_str().unwrap_or("");
                            let created = script["createdDateTime"]
                                .as_str()
                                .unwrap_or("")
                                .split('T')
                                .next()
                                .unwrap_or("");

                            println!("  {} {}", "•".green(), name);
                            if args.detailed {
                                println!("    ID: {}", id.dimmed());
                                println!("    Created: {}", created.dimmed());
                            }
                        }
                    }
                }
            }
            Err(e) => println!("  {} Failed to list: {}", "✗".red(), e),
        }

        // List Proactive Remediations
        println!("\n{} Proactive Remediations:", "→".cyan().bold());

        match graph
            .get_beta::<Value>("deviceManagement/deviceHealthScripts")
            .await
        {
            Ok(response) => {
                if let Some(scripts) = response["value"].as_array() {
                    if scripts.is_empty() {
                        println!("  No proactive remediations found");
                    } else {
                        for script in scripts {
                            let name = script["displayName"].as_str().unwrap_or("Unknown");
                            let publisher = script["publisher"].as_str().unwrap_or("Unknown");
                            let id = script["id"].as_str().unwrap_or("");

                            println!("  {} {} ({})", "•".cyan(), name, publisher.dimmed());
                            if args.detailed {
                                println!("    ID: {}", id.dimmed());
                            }
                        }
                    }
                }
            }
            Err(e) => println!("  {} Failed to list: {}", "✗".red(), e),
        }
    }

    // List macOS scripts
    if args.platform == "all" || args.platform == "macos" {
        println!("\n{} macOS Shell Scripts:", "→".cyan().bold());

        match graph
            .get_beta::<Value>("deviceManagement/deviceShellScripts")
            .await
        {
            Ok(response) => {
                if let Some(scripts) = response["value"].as_array() {
                    if scripts.is_empty() {
                        println!("  No macOS scripts found");
                    } else {
                        for script in scripts {
                            let name = script["displayName"].as_str().unwrap_or("Unknown");
                            let id = script["id"].as_str().unwrap_or("");

                            println!("  {} {}", "•".blue(), name);
                            if args.detailed {
                                println!("    ID: {}", id.dimmed());
                            }
                        }
                    }
                }
            }
            Err(e) => println!("  {} Failed to list: {}", "✗".red(), e),
        }
    }

    Ok(())
}

async fn deploy_windows_script(
    graph: &GraphClient,
    name: &str,
    args: &DeployScriptArgs,
    encoded_content: &str,
) -> Result<()> {
    let script_body = json!({
        "@odata.type": "#microsoft.graph.deviceManagementScript",
        "displayName": name,
        "description": args.description.clone().unwrap_or_else(|| "Deployed via ctl365".to_string()),
        "scriptContent": encoded_content,
        "runAsAccount": if args.run_as_user { "user" } else { "system" },
        "enforceSignatureCheck": args.enforce_signature,
        "runAs32Bit": args.run_as_32bit,
        "fileName": args.file.file_name().and_then(|s| s.to_str()).unwrap_or("script.ps1"),
        "roleScopeTagIds": []
    });

    println!("\n{} Creating Windows PowerShell script...", "→".cyan());

    match graph
        .post_beta::<Value, Value>("deviceManagement/deviceManagementScripts", &script_body)
        .await
    {
        Ok(response) => {
            let script_id = response["id"].as_str().unwrap_or("unknown");
            println!("  {} Script created: {}", "✓".green(), script_id);

            if let Some(group_id) = &args.group_id {
                assign_script_to_group(graph, script_id, group_id, "windows").await?;
            }
        }
        Err(e) => {
            println!("  {} Failed: {}", "✗".red(), e);
        }
    }

    Ok(())
}

async fn deploy_macos_script(
    graph: &GraphClient,
    name: &str,
    args: &DeployScriptArgs,
    encoded_content: &str,
) -> Result<()> {
    let script_body = json!({
        "@odata.type": "#microsoft.graph.deviceShellScript",
        "displayName": name,
        "description": args.description.clone().unwrap_or_else(|| "Deployed via ctl365".to_string()),
        "scriptContent": encoded_content,
        "runAsAccount": if args.run_as_user { "user" } else { "system" },
        "fileName": args.file.file_name().and_then(|s| s.to_str()).unwrap_or("script.sh"),
        "roleScopeTagIds": [],
        "executionFrequency": "PT1H", // Run every hour
        "retryCount": 3,
        "blockExecutionNotifications": true
    });

    println!("\n{} Creating macOS shell script...", "→".cyan());

    match graph
        .post_beta::<Value, Value>("deviceManagement/deviceShellScripts", &script_body)
        .await
    {
        Ok(response) => {
            let script_id = response["id"].as_str().unwrap_or("unknown");
            println!("  {} Script created: {}", "✓".green(), script_id);

            if let Some(group_id) = &args.group_id {
                assign_script_to_group(graph, script_id, group_id, "macos").await?;
            }
        }
        Err(e) => {
            println!("  {} Failed: {}", "✗".red(), e);
        }
    }

    Ok(())
}

async fn deploy_linux_script(
    graph: &GraphClient,
    name: &str,
    args: &DeployScriptArgs,
    encoded_content: &str,
) -> Result<()> {
    // Linux scripts via Intune use custom compliance scripts
    // These require a discovery script (what to check) and a compliance policy
    println!(
        "\n{} Linux script deployment uses custom compliance...",
        "ℹ".yellow()
    );

    // Step 1: Create the custom compliance discovery script
    println!("  {} Creating discovery script...", "→".cyan());

    let discovery_script = json!({
        "@odata.type": "#microsoft.graph.deviceComplianceScript",
        "displayName": format!("{} - Discovery", name),
        "description": args.description.as_deref().unwrap_or("Custom compliance discovery script"),
        "publisher": "ctl365",
        "runAsAccount": if args.run_as_user { "user" } else { "system" },
        "enforceSignatureCheck": false,
        "runAs32Bit": false,
        "scriptContent": encoded_content,
        "roleScopeTagIds": ["0"]
    });

    let script_response: Value = match graph
        .post_beta(
            "deviceManagement/deviceComplianceScripts",
            &discovery_script,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            println!("  {} Failed to create discovery script: {}", "✗".red(), e);
            return Err(e);
        }
    };

    let script_id = script_response["id"]
        .as_str()
        .ok_or_else(|| crate::error::Ctl365Error::GraphApiError("No script ID returned".into()))?;
    println!("  {} Discovery script created: {}", "✓".green(), script_id);

    // Step 2: Create the custom compliance policy
    println!("  {} Creating compliance policy...", "→".cyan());

    let compliance_policy = json!({
        "@odata.type": "#microsoft.graph.linuxCompliancePolicy",
        "displayName": name,
        "description": args.description.as_deref().unwrap_or("Custom compliance policy for Linux"),
        "scheduledActionsForRule": [{
            "ruleName": "PasswordRequired",
            "scheduledActionConfigurations": [{
                "actionType": "block",
                "gracePeriodHours": 0,
                "notificationTemplateId": "",
                "notificationMessageCCList": []
            }]
        }],
        "customComplianceSettings": [{
            "settingId": "customCompliance",
            "deviceComplianceScriptId": script_id,
            "operandDataType": "string",
            "operator": "isEquals",
            "operandValue": "Compliant"
        }],
        "roleScopeTagIds": ["0"]
    });

    let policy_response: Value = match graph
        .post_beta(
            "deviceManagement/deviceCompliancePolicies",
            &compliance_policy,
        )
        .await
    {
        Ok(resp) => resp,
        Err(_e) => {
            // Policy creation might fail if schema differs - try alternative approach
            println!(
                "  {} Standard policy creation failed, trying alternative...",
                "!".yellow()
            );
            // For Linux, we might need to just use the script directly
            if let Some(group_id) = &args.group_id {
                assign_compliance_script_to_group(graph, script_id, group_id).await?;
            }
            return Ok(());
        }
    };

    let policy_id = policy_response["id"].as_str().unwrap_or("unknown");
    println!("  {} Compliance policy created: {}", "✓".green(), policy_id);

    // Step 3: Assign to group if specified
    if let Some(group_id) = &args.group_id {
        println!("  {} Assigning to group...", "→".cyan());
        assign_compliance_policy_to_group(graph, policy_id, group_id).await?;
    }

    println!(
        "\n{} Linux script deployed successfully!",
        "✓".green().bold()
    );
    println!("  Discovery Script ID: {}", script_id);
    println!("  Compliance Policy ID: {}", policy_id);

    Ok(())
}

/// Assign a custom compliance script directly to a group
async fn assign_compliance_script_to_group(
    graph: &GraphClient,
    script_id: &str,
    group_id: &str,
) -> Result<()> {
    let assignment = json!({
        "deviceComplianceScriptAssignments": [{
            "@odata.type": "#microsoft.graph.deviceComplianceScriptAssignment",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": group_id
            },
            "runRemediationScript": false
        }]
    });

    let endpoint = format!(
        "deviceManagement/deviceComplianceScripts/{}/assign",
        script_id
    );

    match graph
        .post_beta::<Value, Value>(&endpoint, &assignment)
        .await
    {
        Ok(_) => println!("  {} Script assigned to group: {}", "✓".green(), group_id),
        Err(e) => println!("  {} Script assignment failed: {}", "✗".red(), e),
    }

    Ok(())
}

/// Assign a compliance policy to a group
async fn assign_compliance_policy_to_group(
    graph: &GraphClient,
    policy_id: &str,
    group_id: &str,
) -> Result<()> {
    let assignment = json!({
        "assignments": [{
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": group_id
            }
        }]
    });

    let endpoint = format!(
        "deviceManagement/deviceCompliancePolicies/{}/assign",
        policy_id
    );

    match graph
        .post_beta::<Value, Value>(&endpoint, &assignment)
        .await
    {
        Ok(_) => println!("  {} Policy assigned to group: {}", "✓".green(), group_id),
        Err(e) => println!("  {} Policy assignment failed: {}", "✗".red(), e),
    }

    Ok(())
}

async fn assign_script_to_group(
    graph: &GraphClient,
    script_id: &str,
    group_id: &str,
    platform: &str,
) -> Result<()> {
    let assignment = json!({
        "deviceManagementScriptGroupAssignments": [{
            "@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment",
            "targetGroupId": group_id
        }]
    });

    let endpoint = match platform {
        "macos" => format!("deviceManagement/deviceShellScripts/{}/assign", script_id),
        _ => format!(
            "deviceManagement/deviceManagementScripts/{}/assign",
            script_id
        ),
    };

    match graph
        .post_beta::<Value, Value>(&endpoint, &assignment)
        .await
    {
        Ok(_) => println!("  {} Assigned to group: {}", "✓".green(), group_id),
        Err(e) => println!("  {} Assignment failed: {}", "✗".red(), e),
    }

    Ok(())
}

async fn assign_remediation_to_group(
    graph: &GraphClient,
    script_id: &str,
    group_id: &str,
) -> Result<()> {
    let assignment = json!({
        "deviceHealthScriptAssignments": [{
            "@odata.type": "#microsoft.graph.deviceHealthScriptAssignment",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": group_id
            },
            "runRemediationScript": true,
            "runSchedule": {
                "@odata.type": "#microsoft.graph.deviceHealthScriptDailySchedule",
                "interval": 1,
                "time": "01:00:00.0000000",
                "useUtc": true
            }
        }]
    });

    let endpoint = format!("deviceManagement/deviceHealthScripts/{}/assign", script_id);

    match graph
        .post_beta::<Value, Value>(&endpoint, &assignment)
        .await
    {
        Ok(_) => println!(
            "  {} Assigned remediation to group: {}",
            "✓".green(),
            group_id
        ),
        Err(e) => println!("  {} Assignment failed: {}", "✗".red(), e),
    }

    Ok(())
}

fn base64_encode(content: &str) -> String {
    use base64::{Engine as _, engine::general_purpose};
    general_purpose::STANDARD.encode(content.as_bytes())
}
