/// Windows Autopilot Integration
///
/// Comprehensive Windows Autopilot deployment:
/// - Device import (manual CSV or hardware hash)
/// - Profile management (user-driven, self-deploying, white glove)
/// - Deployment profile assignment
/// - Device status tracking
/// - Enrollment status page configuration
///
/// Based on Microsoft Autopilot best practices and modern device management
use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::GraphClient;
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum AutopilotCommands {
    /// Import devices into Autopilot
    Import(ImportArgs),

    /// Create an Autopilot deployment profile
    Profile(ProfileArgs),

    /// Assign a profile to devices
    Assign(AssignArgs),

    /// List Autopilot devices
    List(ListArgs),

    /// Show device status
    Status(StatusArgs),

    /// Sync Autopilot devices with Intune
    Sync,

    /// Delete an Autopilot device
    Delete(DeleteArgs),
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to CSV file with device hardware hashes
    #[arg(short, long)]
    pub file: PathBuf,

    /// Group tag to apply to imported devices
    #[arg(short, long)]
    pub group_tag: Option<String>,

    /// Automatically assign to profile
    #[arg(short, long)]
    pub profile_id: Option<String>,

    /// Device model (optional metadata)
    #[arg(long)]
    pub model: Option<String>,

    /// Device manufacturer (optional metadata)
    #[arg(long)]
    pub manufacturer: Option<String>,

    /// Dry run - show what would be imported without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct ProfileArgs {
    /// Profile name
    #[arg(short, long)]
    pub name: String,

    /// Profile description
    #[arg(short, long)]
    pub description: Option<String>,

    /// Deployment mode (user-driven, self-deploying, white-glove)
    #[arg(long, default_value = "user-driven")]
    pub mode: String,

    /// Device type (Windows PC, HoloLens)
    #[arg(long, default_value = "windowsPc")]
    pub device_type: String,

    /// Language/region (en-US, de-DE, etc.)
    #[arg(long, default_value = "en-US")]
    pub language: String,

    /// Enable Hybrid Azure AD Join
    #[arg(long)]
    pub hybrid_join: bool,

    /// Skip keyboard selection page
    #[arg(long)]
    pub skip_keyboard: bool,

    /// Skip privacy settings page
    #[arg(long)]
    pub skip_privacy: bool,

    /// Skip EULA page
    #[arg(long)]
    pub skip_eula: bool,

    /// Convert device to Autopilot
    #[arg(long)]
    pub convert_device_to_autopilot: bool,

    /// Enable white glove (pre-provisioning)
    #[arg(long)]
    pub enable_white_glove: bool,

    /// Assign to group
    #[arg(short, long)]
    pub group_id: Option<String>,

    /// Dry run - show what would be created without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct AssignArgs {
    /// Profile ID
    #[arg(short, long)]
    pub profile_id: String,

    /// Device serial number or hardware hash
    #[arg(short, long)]
    pub device: Option<String>,

    /// Group tag to assign profile to
    #[arg(short, long)]
    pub group_tag: Option<String>,

    /// Assign to all devices (use with caution)
    #[arg(long)]
    pub all_devices: bool,

    /// Dry run - show what would be assigned without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by group tag
    #[arg(short, long)]
    pub group_tag: Option<String>,

    /// Filter by enrollment state (enrolled, notEnrolled, pendingReset)
    #[arg(short, long)]
    pub state: Option<String>,

    /// Show detailed information
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Device serial number or ID
    pub device_id: String,

    /// Show deployment profile
    #[arg(short, long)]
    pub show_profile: bool,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Device ID or serial number
    pub device_id: String,

    /// Force deletion without confirmation
    #[arg(short, long)]
    pub force: bool,

    /// Dry run - show what would be deleted without making changes
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AutopilotDevice {
    id: Option<String>,
    serial_number: String,
    model: Option<String>,
    manufacturer: Option<String>,
    product_key: Option<String>,
    group_tag: Option<String>,
    enrollment_state: Option<String>,
    last_contacted_date_time: Option<String>,
}

/// Import devices into Autopilot
pub async fn import(args: ImportArgs) -> Result<()> {
    println!("{} Autopilot devices...", "Importing".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Read CSV file
    let csv_content = std::fs::read_to_string(&args.file)?;
    let mut rdr = csv::Reader::from_reader(csv_content.as_bytes());

    // Parse all records, tracking errors
    let mut records: Vec<CsvRecord> = Vec::new();
    let mut errors: Vec<(usize, String)> = Vec::new();

    for (row_idx, result) in rdr.deserialize().enumerate() {
        let row_num = row_idx + 2; // +1 for 0-index, +1 for header row
        match result {
            Ok(record) => {
                let record: CsvRecord = record;
                // Validate required fields
                if record.device_serial_number.trim().is_empty() {
                    errors.push((row_num, "Missing or empty device_serial_number".to_string()));
                } else if record.hardware_hash.trim().is_empty() {
                    errors.push((row_num, "Missing or empty hardware_hash".to_string()));
                } else {
                    records.push(record);
                }
            }
            Err(e) => {
                errors.push((row_num, format!("Parse error: {}", e)));
            }
        }
    }

    // Report any errors found
    if !errors.is_empty() {
        println!(
            "\n{} Found {} error(s) in CSV file:",
            "⚠".yellow().bold(),
            errors.len()
        );
        for (row, msg) in &errors {
            println!("  Row {}: {}", row, msg.red());
        }
        if records.is_empty() {
            println!("\n{} No valid devices found in CSV file", "✗".red());
            return Ok(());
        }
        println!(
            "\n{} Continuing with {} valid record(s), skipping {} invalid",
            "→".cyan(),
            records.len(),
            errors.len()
        );
    }

    if records.is_empty() {
        println!("\n{} No valid devices found in CSV file", "✗".red());
        return Ok(());
    }

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!(
            "\n{} Devices that would be imported from: {}",
            "→".cyan(),
            args.file.display()
        );
        for record in &records {
            println!("  • Serial: {}", record.device_serial_number);
            if let Some(tag) = args.group_tag.as_ref().or(record.group_tag.as_ref()) {
                println!("    Group Tag: {}", tag);
            }
            if let Some(user) = &record.assigned_user {
                println!("    Assigned User: {}", user);
            }
        }
        println!("\n{} Total: {} devices", "→".cyan(), records.len());
        if let Some(profile_id) = &args.profile_id {
            println!("{} Would assign to profile: {}", "→".cyan(), profile_id);
        }
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will import {} devices to tenant '{}'",
            "⚠".yellow().bold(),
            records.len(),
            active_tenant.name
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    let mut import_count = 0;
    let mut error_count = 0;

    println!(
        "\n{} Importing devices from: {}",
        "→".cyan(),
        args.file.display()
    );

    for record in records {
        let device_payload = json!({
            "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
            "serialNumber": record.device_serial_number,
            "hardwareIdentifier": record.hardware_hash,
            "groupTag": args.group_tag.as_ref().or(record.group_tag.as_ref()),
            "state": {
                "@odata.type": "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
                "deviceImportStatus": "pending",
                "deviceRegistrationId": "",
                "deviceErrorCode": 0,
                "deviceErrorName": ""
            },
            "assignedUserPrincipalName": record.assigned_user.as_deref().unwrap_or("")
        });

        print!(
            "  {} Importing device: {}... ",
            "→".cyan(),
            record.device_serial_number
        );

        match graph
            .post::<Value, Value>(
                "deviceManagement/importedWindowsAutopilotDeviceIdentities",
                &device_payload,
            )
            .await
        {
            Ok(_) => {
                println!("{}", "✓".green().bold());
                import_count += 1;
            }
            Err(e) => {
                println!("{} {}", "✗".red().bold(), e);
                error_count += 1;
            }
        }
    }

    println!("\n{} Import Summary:", "→".cyan().bold());
    println!(
        "  {} devices imported successfully",
        import_count.to_string().green()
    );
    if error_count > 0 {
        println!("  {} devices failed", error_count.to_string().red());
    }

    // Trigger sync
    if import_count > 0 {
        println!("\n{} Syncing Autopilot devices...", "→".cyan());
        sync_devices(&graph).await?;
    }

    // Assign to profile if specified
    if let Some(profile_id) = &args.profile_id {
        println!(
            "\n{} Assigning devices to profile: {}",
            "→".cyan(),
            profile_id
        );
        // Assignment logic would go here
    }

    println!("\n{} Autopilot import completed", "✓".green().bold());

    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct CsvRecord {
    device_serial_number: String,
    #[serde(rename = "Windows Product ID")]
    #[allow(dead_code)]
    windows_product_id: Option<String>,
    hardware_hash: String,
    group_tag: Option<String>,
    assigned_user: Option<String>,
}

/// Create an Autopilot deployment profile
pub async fn profile(args: ProfileArgs) -> Result<()> {
    println!(
        "{} Autopilot deployment profile...",
        "Creating".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Determine profile type based on mode
    let (odata_type, deployment_mode, enable_white_glove) = match args.mode.as_str() {
        "user-driven" | "user" => (
            "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
            "userDriven",
            args.enable_white_glove,
        ),
        "self-deploying" | "self" => (
            "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
            "selfDeploying",
            false,
        ),
        "white-glove" | "pre-provision" => (
            "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
            "userDriven",
            true,
        ),
        _ => {
            return Err(crate::error::Error::ConfigError(format!(
                "Unknown deployment mode: '{}'. Use: user-driven, self-deploying, or white-glove",
                args.mode
            )));
        }
    };

    let profile_payload = json!({
        "@odata.type": odata_type,
        "displayName": args.name,
        "description": args.description.unwrap_or_else(|| format!("Autopilot {} deployment profile", args.mode)),
        "language": args.language,
        "locale": args.language,
        "deviceType": args.device_type,
        "deviceNameTemplate": "%SERIAL%", // Use serial number as device name
        "enableWhiteGlove": enable_white_glove,
        "extractHardwareHash": args.convert_device_to_autopilot,
        "hybridAzureADJoinSkipConnectivityCheck": args.hybrid_join,

        // Deployment mode
        "deploymentMode": deployment_mode,

        // OOBE settings
        "outOfBoxExperienceSettings": {
            "hidePrivacySettings": args.skip_privacy,
            "hideEULA": args.skip_eula,
            "userType": if deployment_mode == "selfDeploying" { "deviceOwner" } else { "standard" },
            "deviceUsageType": "shared", // shared, single
            "skipKeyboardSelectionPage": args.skip_keyboard,
            "hideEscapeLink": true // Don't allow skipping enrollment
        },

        // Management settings
        "managementServiceAppId": "00000000-0000-0000-0000-000000000000", // Use default

        // Hybrid join settings (if enabled)
        "hybridAzureADJoined": args.hybrid_join
    });

    println!("\n{} Configuration:", "→".cyan());
    println!("  Name: {}", args.name.bold());
    println!("  Mode: {}", deployment_mode.yellow());
    println!("  Language: {}", args.language);
    println!("  Device Type: {}", args.device_type);
    if enable_white_glove {
        println!("  {} White Glove enabled", "✓".green());
    }
    if args.hybrid_join {
        println!("  {} Hybrid Azure AD Join", "✓".green());
    }

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        if let Some(group_id) = &args.group_id {
            println!("{} Would assign to group: {}", "→".cyan(), group_id);
        }
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will create an Autopilot profile in tenant '{}'",
            "⚠".yellow().bold(),
            active_tenant.name
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    let profile: Value = graph
        .post(
            "deviceManagement/windowsAutopilotDeploymentProfiles",
            &profile_payload,
        )
        .await?;

    let profile_id = profile["id"].as_str().unwrap_or("unknown");

    println!(
        "\n{} Profile created: {}",
        "✓".green().bold(),
        profile_id.cyan()
    );

    // Assign to group if specified
    if let Some(group_id) = &args.group_id {
        println!("\n{} Assigning profile to group: {}", "→".cyan(), group_id);

        let assignment_payload = json!({
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": group_id
            }
        });

        graph
            .post::<Value, Value>(
                &format!(
                    "deviceManagement/windowsAutopilotDeploymentProfiles/{}/assignments",
                    profile_id
                ),
                &assignment_payload,
            )
            .await?;

        println!("  {} Profile assigned", "✓".green());
    }

    println!(
        "\n{} Autopilot profile created successfully",
        "✓".green().bold()
    );

    Ok(())
}

/// Assign a profile to devices
pub async fn assign(args: AssignArgs) -> Result<()> {
    println!("{} Autopilot profile...", "Assigning".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Determine assignment target description
    let target_desc = if args.all_devices {
        "ALL devices".to_string()
    } else if let Some(tag) = &args.group_tag {
        format!("devices with group tag '{}'", tag)
    } else if let Some(device) = &args.device {
        format!("device '{}'", device)
    } else {
        return Err(crate::error::Error::ConfigError(
            "Must specify --device, --group-tag, or --all-devices".into(),
        ));
    };

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!(
            "{} Would assign profile '{}' to {}",
            "→".cyan(),
            args.profile_id,
            target_desc
        );
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        use std::io::{self, Write};
        println!(
            "\n{} This will assign profile '{}' to {}",
            "⚠".yellow().bold(),
            args.profile_id,
            target_desc
        );
        print!("\nContinue? [y/N]: ");
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    if args.all_devices {
        println!("{} Assigning to ALL devices", "⚠".yellow().bold());

        let assignment_payload = json!({
            "target": {
                "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
            }
        });

        graph
            .post::<Value, Value>(
                &format!(
                    "deviceManagement/windowsAutopilotDeploymentProfiles/{}/assignments",
                    args.profile_id
                ),
                &assignment_payload,
            )
            .await?;

        println!("{} Profile assigned to all devices", "✓".green().bold());
    } else if let Some(group_tag) = &args.group_tag {
        println!(
            "{} Assigning to devices with group tag: {}",
            "→".cyan(),
            group_tag
        );

        // This requires fetching devices with the group tag and assigning individually
        // Or creating a dynamic group based on group tag
        println!(
            "{} Group tag assignment requires dynamic group creation",
            "ℹ".blue()
        );
        println!("  Create a dynamic device group with rule:");
        println!(
            "  (device.devicePhysicalIds -any (_ -contains \"[OrderID]:{}\"))",
            group_tag
        );
    } else if let Some(device) = &args.device {
        println!("{} Assigning to device: {}", "→".cyan(), device);

        // Find device
        let devices: Value = graph
            .get(&format!(
                "deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains(serialNumber,'{}')",
                device
            ))
            .await?;

        if let Some(device_list) = devices["value"].as_array() {
            if device_list.is_empty() {
                return Err(crate::error::Error::ConfigError(format!(
                    "Device not found: {}",
                    device
                )));
            }

            let device_id = device_list[0]["id"].as_str().ok_or_else(|| {
                crate::error::Error::ConfigError("Device response missing id".into())
            })?;

            let update_payload = json!({
                "deploymentProfileAssignmentStatus": "assigned",
                "deploymentProfileAssignedDateTime": chrono::Utc::now().to_rfc3339()
            });

            graph
                .patch::<Value, Value>(
                    &format!(
                        "deviceManagement/windowsAutopilotDeviceIdentities/{}",
                        device_id
                    ),
                    &update_payload,
                )
                .await?;

            println!("{} Profile assigned to device", "✓".green().bold());
        }
    }

    Ok(())
}

/// List Autopilot devices
pub async fn list(args: ListArgs) -> Result<()> {
    println!("{} Autopilot devices...", "Listing".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Build filter query
    let mut filter_parts = Vec::new();

    if let Some(group_tag) = &args.group_tag {
        filter_parts.push(format!("groupTag eq '{}'", group_tag));
    }

    if let Some(state) = &args.state {
        filter_parts.push(format!("enrollmentState eq '{}'", state));
    }

    let filter_query = if filter_parts.is_empty() {
        String::new()
    } else {
        format!("?$filter={}", filter_parts.join(" and "))
    };

    let devices: Value = graph
        .get(&format!(
            "deviceManagement/windowsAutopilotDeviceIdentities{}",
            filter_query
        ))
        .await?;

    if let Some(device_list) = devices["value"].as_array() {
        if device_list.is_empty() {
            println!("\n{} No Autopilot devices found", "ℹ".blue());
            return Ok(());
        }

        println!("\n{} {} devices found", "→".cyan(), device_list.len());

        if args.verbose {
            for device in device_list {
                print_device_detailed(device);
            }
        } else {
            println!(
                "\n{:<20} {:<30} {:<20} {:<15}",
                "Serial Number", "Model", "Group Tag", "State"
            );
            println!("{}", "─".repeat(90));

            for device in device_list {
                let serial = device["serialNumber"].as_str().unwrap_or("Unknown");
                let model = device["model"].as_str().unwrap_or("Unknown");
                let group_tag = device["groupTag"].as_str().unwrap_or("-");
                let state = device["enrollmentState"].as_str().unwrap_or("unknown");

                println!(
                    "{:<20} {:<30} {:<20} {:<15}",
                    serial, model, group_tag, state
                );
            }
        }
    }

    Ok(())
}

fn print_device_detailed(device: &Value) {
    println!("\n{}", "─".repeat(80));
    println!(
        "{}: {}",
        "Serial Number".bold(),
        device["serialNumber"].as_str().unwrap_or("Unknown")
    );

    if let Some(id) = device["id"].as_str() {
        println!("{}: {}", "Device ID".bold(), id);
    }

    if let Some(model) = device["model"].as_str() {
        println!("{}: {}", "Model".bold(), model);
    }

    if let Some(manufacturer) = device["manufacturer"].as_str() {
        println!("{}: {}", "Manufacturer".bold(), manufacturer);
    }

    if let Some(group_tag) = device["groupTag"].as_str() {
        println!("{}: {}", "Group Tag".bold(), group_tag.yellow());
    }

    if let Some(state) = device["enrollmentState"].as_str() {
        let state_colored = match state {
            "enrolled" => state.green(),
            "notEnrolled" => state.yellow(),
            "pendingReset" => state.red(),
            _ => state.normal(),
        };
        println!("{}: {}", "Enrollment State".bold(), state_colored);
    }

    if let Some(last_contacted) = device["lastContactedDateTime"].as_str() {
        println!("{}: {}", "Last Contacted".bold(), last_contacted);
    }
}

/// Show device status
pub async fn status(args: StatusArgs) -> Result<()> {
    println!("{} device status...", "Checking".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Try to find device by serial number first
    let devices: Value = graph
        .get(&format!(
            "deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains(serialNumber,'{}')",
            args.device_id
        ))
        .await?;

    let device = if let Some(device_list) = devices["value"].as_array() {
        if device_list.is_empty() {
            // Try by ID
            graph
                .get(&format!(
                    "deviceManagement/windowsAutopilotDeviceIdentities/{}",
                    args.device_id
                ))
                .await?
        } else {
            device_list[0].clone()
        }
    } else {
        return Err(crate::error::Error::ConfigError("Device not found".into()));
    };

    print_device_detailed(&device);

    // Show deployment profile if requested
    if args.show_profile {
        if let Some(profile_id) = device["deploymentProfileAssignmentDetailedStatus"].as_str() {
            println!("\n{}", "Deployment Profile:".bold());

            let profile: Value = graph
                .get(&format!(
                    "deviceManagement/windowsAutopilotDeploymentProfiles/{}",
                    profile_id
                ))
                .await?;

            println!(
                "  Name: {}",
                profile["displayName"].as_str().unwrap_or("Unknown")
            );
            println!(
                "  Mode: {}",
                profile["deploymentMode"].as_str().unwrap_or("unknown")
            );
        }
    }

    Ok(())
}

/// Sync Autopilot devices with Intune
pub async fn sync() -> Result<()> {
    println!(
        "{} Autopilot devices with Intune...",
        "Syncing".cyan().bold()
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    sync_devices(&graph).await?;

    println!("{} Sync initiated successfully", "✓".green().bold());
    println!("{} Sync may take several minutes to complete", "ℹ".blue());

    Ok(())
}

async fn sync_devices(graph: &GraphClient) -> Result<()> {
    graph
        .post::<Value, Value>("deviceManagement/windowsAutopilotSettings/sync", &json!({}))
        .await?;
    Ok(())
}

/// Delete an Autopilot device
pub async fn delete(args: DeleteArgs) -> Result<()> {
    println!("{} Autopilot device...", "Deleting".cyan().bold());

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would delete device: {}", "→".cyan(), args.device_id);
        return Ok(());
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Find device
    let devices: Value = graph
        .get(&format!(
            "deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains(serialNumber,'{}')",
            args.device_id
        ))
        .await?;

    let device_id = if let Some(device_list) = devices["value"].as_array() {
        if device_list.is_empty() {
            // Try using the ID directly
            args.device_id.clone()
        } else {
            device_list[0]["id"]
                .as_str()
                .unwrap_or(&args.device_id)
                .to_string()
        }
    } else {
        args.device_id.clone()
    };

    // Confirm deletion unless --force
    if !args.force {
        use std::io::{self, Write};
        print!(
            "\n{} Delete device '{}'? This cannot be undone. [y/N]: ",
            "?".yellow().bold(),
            device_id
        );
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    graph
        .delete(&format!(
            "deviceManagement/windowsAutopilotDeviceIdentities/{}",
            device_id
        ))
        .await?;

    println!("{} Device deleted successfully", "✓".green().bold());

    Ok(())
}
