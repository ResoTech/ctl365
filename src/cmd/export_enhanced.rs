/// Enhanced Export/Import with assignment migration and conflict resolution
///
/// Supports:
/// - Settings Catalog policies
/// - Assignment migration with group mapping
/// - Incremental sync (skip existing policies)
/// - Conflict resolution strategies
use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{GraphClient, conditional_access, intune};
use clap::Args;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output directory for exported policies
    #[arg(short, long, default_value = "./export")]
    pub output: PathBuf,

    /// Export specific policy types (comma-separated: compliance,configuration,settings-catalog,ca,all)
    #[arg(long, default_value = "all")]
    pub types: String,

    /// Include assignments in export
    #[arg(long)]
    pub include_assignments: bool,

    /// Include group details for assignment mapping
    #[arg(long)]
    pub include_group_details: bool,

    /// Tenant to export from (defaults to active tenant)
    #[arg(long)]
    pub tenant: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Input directory containing exported policies
    #[arg(short, long)]
    pub input: PathBuf,

    /// Import mode: create, replace, update, skip-existing
    #[arg(long, default_value = "create")]
    pub mode: String,

    /// Migrate assignments to new groups
    #[arg(long)]
    pub migrate_assignments: bool,

    /// Assignment mapping file (JSON: {"source_group_id": "target_group_id"})
    #[arg(long)]
    pub assignment_map: Option<PathBuf>,

    /// Automatically create missing groups
    #[arg(long)]
    pub create_missing_groups: bool,

    /// Dry run - show what would be imported
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct ExportMetadata {
    export_date: String,
    tenant_id: String,
    tenant_name: String,
    total_policies: usize,
    include_assignments: bool,
    include_group_details: bool,
    types: String,
    ctl365_version: String,
    policy_counts: PolicyCounts,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct PolicyCounts {
    compliance_policies: usize,
    device_configurations: usize,
    settings_catalog: usize,
    conditional_access: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyWithAssignments {
    policy: Value,
    assignments: Vec<Assignment>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Assignment {
    id: String,
    target: AssignmentTarget,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AssignmentTarget {
    #[serde(rename = "@odata.type")]
    odata_type: String,
    group_id: Option<String>,
    group_name: Option<String>,
    group_display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GroupMapping {
    source_group_id: String,
    source_group_name: String,
    target_group_id: Option<String>,
    target_group_name: Option<String>,
    mapping_strategy: String, // "exact_match", "manual", "create_new"
}

/// Create a spinner for async operations
#[allow(dead_code)]
fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));
    spinner
}

/// Export all policies with assignments
pub async fn export_enhanced(args: ExportArgs) -> Result<()> {
    println!("{} policies from tenant...", "Exporting".cyan().bold());

    let config = ConfigManager::load()?;
    let tenant_name = if let Some(ref t) = args.tenant {
        t.clone()
    } else {
        config
            .get_active_tenant()
            .ok()
            .flatten()
            .map(|t| t.name.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };

    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Tenant: {}", tenant_name.cyan().bold());
    println!("→ Output: {}", args.output.display().to_string().cyan());
    println!(
        "→ Include Assignments: {}",
        if args.include_assignments {
            "Yes"
        } else {
            "No"
        }
    );

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Create output directories
    fs::create_dir_all(&args.output)?;
    let compliance_dir = args.output.join("CompliancePolicies");
    let config_dir = args.output.join("DeviceConfigurations");
    let settings_catalog_dir = args.output.join("SettingsCatalog");
    let ca_dir = args.output.join("ConditionalAccess");
    let assignments_dir = args.output.join("Assignments");

    fs::create_dir_all(&compliance_dir)?;
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(&settings_catalog_dir)?;
    fs::create_dir_all(&ca_dir)?;

    if args.include_assignments {
        fs::create_dir_all(&assignments_dir)?;
    }

    let mut total_exported = 0;
    let mut policy_counts = PolicyCounts {
        compliance_policies: 0,
        device_configurations: 0,
        settings_catalog: 0,
        conditional_access: 0,
    };

    let mut all_groups = HashMap::new();

    // Get all groups if we need group details
    if args.include_group_details {
        println!("\n{} Azure AD groups for mapping...", "→".cyan());
        match get_all_groups(&graph).await {
            Ok(groups) => {
                for group in groups {
                    if let (Some(id), Some(name)) =
                        (group["id"].as_str(), group["displayName"].as_str())
                    {
                        all_groups.insert(id.to_string(), name.to_string());
                    }
                }
                println!("  {} Found {} groups", "✓".green(), all_groups.len());
            }
            Err(e) => println!("  {} Failed to get groups: {}", "✗".red(), e),
        }
    }

    // Export Compliance Policies
    if args.types == "all" || args.types.contains("compliance") {
        println!("\n{} Compliance Policies...", "→".cyan());
        match intune::list_compliance_policies(&graph).await {
            Ok(policies) => {
                if let Some(policy_list) = policies["value"].as_array() {
                    for policy in policy_list {
                        let name = policy["displayName"].as_str().unwrap_or("Unknown");
                        let id = policy["id"].as_str().unwrap_or("unknown");

                        let filename = format!("{}.json", sanitize_filename(name));
                        let filepath = compliance_dir.join(&filename);

                        // Get assignments if requested
                        let assignments = if args.include_assignments {
                            get_policy_assignments(&graph, id, "compliance", &all_groups).await?
                        } else {
                            vec![]
                        };

                        let policy_with_assignments = PolicyWithAssignments {
                            policy: policy.clone(),
                            assignments: assignments.clone(),
                        };

                        fs::write(
                            &filepath,
                            serde_json::to_string_pretty(&policy_with_assignments)?,
                        )?;

                        if args.include_assignments && !assignments.is_empty() {
                            let assignment_file = assignments_dir
                                .join(format!("compliance_{}.json", sanitize_filename(name)));
                            fs::write(
                                &assignment_file,
                                serde_json::to_string_pretty(&assignments)?,
                            )?;
                        }

                        println!("  {} {}", "✓".green(), name);
                        total_exported += 1;
                        policy_counts.compliance_policies += 1;
                    }
                }
            }
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    // Export Device Configurations (Legacy)
    if args.types == "all" || args.types.contains("configuration") {
        println!("\n{} Device Configurations...", "→".cyan());
        match intune::list_device_configurations(&graph).await {
            Ok(configs) => {
                if let Some(config_list) = configs["value"].as_array() {
                    for config in config_list {
                        let name = config["displayName"].as_str().unwrap_or("Unknown");
                        let id = config["id"].as_str().unwrap_or("unknown");

                        let filename = format!("{}.json", sanitize_filename(name));
                        let filepath = config_dir.join(&filename);

                        let assignments = if args.include_assignments {
                            get_policy_assignments(&graph, id, "deviceConfiguration", &all_groups)
                                .await?
                        } else {
                            vec![]
                        };

                        let policy_with_assignments = PolicyWithAssignments {
                            policy: config.clone(),
                            assignments: assignments.clone(),
                        };

                        fs::write(
                            &filepath,
                            serde_json::to_string_pretty(&policy_with_assignments)?,
                        )?;

                        println!("  {} {}", "✓".green(), name);
                        total_exported += 1;
                        policy_counts.device_configurations += 1;
                    }
                }
            }
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    // Export Settings Catalog Policies
    if args.types == "all" || args.types.contains("settings-catalog") {
        println!("\n{} Settings Catalog Policies...", "→".cyan());
        match list_settings_catalog_policies(&graph).await {
            Ok(catalog_policies) => {
                if let Some(catalog_list) = catalog_policies["value"].as_array() {
                    for catalog_policy in catalog_list {
                        let name = catalog_policy["name"].as_str().unwrap_or("Unknown");
                        let id = catalog_policy["id"].as_str().unwrap_or("unknown");

                        let filename = format!("{}.json", sanitize_filename(name));
                        let filepath = settings_catalog_dir.join(&filename);

                        // Get full policy with settings
                        let full_policy = get_settings_catalog_policy(&graph, id).await?;

                        let assignments = if args.include_assignments {
                            get_settings_catalog_assignments(&graph, id, &all_groups).await?
                        } else {
                            vec![]
                        };

                        let policy_with_assignments = PolicyWithAssignments {
                            policy: full_policy,
                            assignments: assignments.clone(),
                        };

                        fs::write(
                            &filepath,
                            serde_json::to_string_pretty(&policy_with_assignments)?,
                        )?;

                        println!("  {} {}", "✓".green(), name);
                        total_exported += 1;
                        policy_counts.settings_catalog += 1;
                    }
                }
            }
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    // Export Conditional Access Policies
    if args.types == "all" || args.types.contains("ca") {
        println!("\n{} Conditional Access Policies...", "→".cyan());
        match conditional_access::list_policies(&graph).await {
            Ok(ca_policies) => {
                if let Some(ca_list) = ca_policies["value"].as_array() {
                    for ca_policy in ca_list {
                        let name = ca_policy["displayName"].as_str().unwrap_or("Unknown");
                        let filename = format!("{}.json", sanitize_filename(name));
                        let filepath = ca_dir.join(&filename);

                        // CA policies don't have separate assignments - conditions are built-in
                        fs::write(&filepath, serde_json::to_string_pretty(ca_policy)?)?;

                        println!("  {} {}", "✓".green(), name);
                        total_exported += 1;
                        policy_counts.conditional_access += 1;
                    }
                }
            }
            Err(e) => println!("  {} Failed: {}", "✗".red(), e),
        }
    }

    // Create export metadata
    let metadata = ExportMetadata {
        export_date: chrono::Utc::now().to_rfc3339(),
        tenant_id: active_tenant.tenant_id.clone(),
        tenant_name: tenant_name.clone(),
        total_policies: total_exported,
        include_assignments: args.include_assignments,
        include_group_details: args.include_group_details,
        types: args.types.clone(),
        ctl365_version: env!("CARGO_PKG_VERSION").to_string(),
        policy_counts,
    };

    fs::write(
        args.output.join("export_metadata.json"),
        serde_json::to_string_pretty(&metadata)?,
    )?;

    // Save group mapping template if groups were collected
    if args.include_group_details && !all_groups.is_empty() {
        let group_map: Vec<GroupMapping> = all_groups
            .iter()
            .map(|(id, name)| GroupMapping {
                source_group_id: id.clone(),
                source_group_name: name.clone(),
                target_group_id: None,
                target_group_name: None,
                mapping_strategy: "manual".to_string(),
            })
            .collect();

        fs::write(
            args.output.join("group_mapping_template.json"),
            serde_json::to_string_pretty(&group_map)?,
        )?;

        println!(
            "\n{} Group mapping template saved to: {}",
            "✓".green().bold(),
            args.output.join("group_mapping_template.json").display()
        );
    }

    println!(
        "\n{} Exported {} policies to {}",
        "✓".green().bold(),
        total_exported,
        args.output.display()
    );

    println!("\n{}", "Policy Breakdown:".cyan().bold());
    println!(
        "  Compliance Policies: {}",
        policy_counts.compliance_policies
    );
    println!(
        "  Device Configurations: {}",
        policy_counts.device_configurations
    );
    println!("  Settings Catalog: {}", policy_counts.settings_catalog);
    println!("  Conditional Access: {}", policy_counts.conditional_access);

    Ok(())
}

/// Import policies with assignment migration
pub async fn import_enhanced(args: ImportArgs) -> Result<()> {
    println!("{} policies to tenant...", "Importing".cyan().bold());

    if !args.input.exists() {
        return Err(crate::error::Error::ConfigError(format!(
            "Import directory does not exist: {}",
            args.input.display()
        )));
    }

    // Read metadata
    let metadata_path = args.input.join("export_metadata.json");
    let metadata: ExportMetadata = if metadata_path.exists() {
        let metadata_str = fs::read_to_string(&metadata_path)?;
        serde_json::from_str(&metadata_str)?
    } else {
        return Err(crate::error::Error::ConfigError(
            "No export_metadata.json found in import directory".into(),
        ));
    };

    println!(
        "→ Source: {} (exported {})",
        metadata.tenant_name, metadata.export_date
    );

    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("→ Target: {}", active_tenant.name.cyan().bold());
    println!("→ Mode: {}", args.mode.yellow());

    // Load assignment mapping if provided
    let assignment_map: HashMap<String, String> = if let Some(map_file) = &args.assignment_map {
        let map_str = fs::read_to_string(map_file)?;
        serde_json::from_str(&map_str)?
    } else {
        HashMap::new()
    };

    if args.migrate_assignments && !assignment_map.is_empty() {
        println!(
            "→ Assignment Mapping: {} group mappings loaded",
            assignment_map.len()
        );
    }

    if !args.yes && !args.dry_run {
        use std::io::{self, Write};
        print!(
            "\n{} Import {} policies to tenant '{}'? [y/N]: ",
            "?".yellow().bold(),
            metadata.total_policies,
            active_tenant.name
        );
        io::stdout().flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !response.trim().eq_ignore_ascii_case("y") {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;
    let mut total_imported = 0;
    let mut total_skipped = 0;
    let mut total_errors = 0;

    // Get existing policies if mode is skip-existing or update
    let existing_policies = if args.mode == "skip-existing" || args.mode == "update" {
        get_existing_policy_names(&graph).await?
    } else {
        HashMap::new()
    };

    // Import Compliance Policies
    let compliance_dir = args.input.join("CompliancePolicies");
    if compliance_dir.exists() {
        println!("\n{} Compliance Policies...", "→".cyan());
        for entry in fs::read_dir(compliance_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                let policy_with_assignments: PolicyWithAssignments =
                    serde_json::from_str(&content)?;

                let name = policy_with_assignments.policy["displayName"]
                    .as_str()
                    .unwrap_or("Unknown");

                // Check if policy already exists
                if args.mode == "skip-existing" && existing_policies.contains_key(name) {
                    println!("  {} Skipped (already exists): {}", "→".cyan(), name);
                    total_skipped += 1;
                    continue;
                }

                if args.dry_run {
                    println!("  {} would import: {}", "→".cyan(), name);
                    if args.migrate_assignments && !policy_with_assignments.assignments.is_empty() {
                        println!(
                            "    {} {} assignments",
                            "→".cyan(),
                            policy_with_assignments.assignments.len()
                        );
                    }
                } else {
                    // Import policy
                    match import_compliance_policy(
                        &graph,
                        &policy_with_assignments.policy,
                        &args.mode,
                    )
                    .await
                    {
                        Ok(new_policy) => {
                            println!("  {} {}", "✓".green(), name);

                            // Migrate assignments if requested
                            if args.migrate_assignments
                                && !policy_with_assignments.assignments.is_empty()
                            {
                                let new_policy_id = new_policy["id"].as_str().unwrap_or("");
                                match migrate_policy_assignments(
                                    &graph,
                                    new_policy_id,
                                    "compliance",
                                    &policy_with_assignments.assignments,
                                    &assignment_map,
                                    args.create_missing_groups,
                                )
                                .await
                                {
                                    Ok(migrated) => {
                                        println!("    {} {} assignments", "✓".green(), migrated)
                                    }
                                    Err(e) => println!(
                                        "    {} Assignment migration failed: {}",
                                        "✗".red(),
                                        e
                                    ),
                                }
                            }

                            total_imported += 1;
                        }
                        Err(e) => {
                            println!("  {} Failed {}: {}", "✗".red(), name, e);
                            total_errors += 1;
                        }
                    }
                }
            }
        }
    }

    // Import Device Configurations
    let config_dir = args.input.join("DeviceConfigurations");
    if config_dir.exists() {
        println!("\n{} Device Configurations...", "→".cyan());
        for entry in fs::read_dir(config_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                let policy_with_assignments: PolicyWithAssignments =
                    serde_json::from_str(&content)?;

                let name = policy_with_assignments.policy["displayName"]
                    .as_str()
                    .unwrap_or("Unknown");

                if args.mode == "skip-existing" && existing_policies.contains_key(name) {
                    println!("  {} Skipped (already exists): {}", "→".cyan(), name);
                    total_skipped += 1;
                    continue;
                }

                if args.dry_run {
                    println!("  {} would import: {}", "→".cyan(), name);
                } else {
                    match import_device_configuration(
                        &graph,
                        &policy_with_assignments.policy,
                        &args.mode,
                    )
                    .await
                    {
                        Ok(new_policy) => {
                            println!("  {} {}", "✓".green(), name);

                            if args.migrate_assignments
                                && !policy_with_assignments.assignments.is_empty()
                            {
                                let new_policy_id = new_policy["id"].as_str().unwrap_or("");
                                match migrate_policy_assignments(
                                    &graph,
                                    new_policy_id,
                                    "deviceConfiguration",
                                    &policy_with_assignments.assignments,
                                    &assignment_map,
                                    args.create_missing_groups,
                                )
                                .await
                                {
                                    Ok(migrated) => {
                                        println!("    {} {} assignments", "✓".green(), migrated)
                                    }
                                    Err(e) => println!(
                                        "    {} Assignment migration failed: {}",
                                        "✗".red(),
                                        e
                                    ),
                                }
                            }

                            total_imported += 1;
                        }
                        Err(e) => {
                            println!("  {} Failed {}: {}", "✗".red(), name, e);
                            total_errors += 1;
                        }
                    }
                }
            }
        }
    }

    // Import Settings Catalog Policies
    let settings_catalog_dir = args.input.join("SettingsCatalog");
    if settings_catalog_dir.exists() {
        println!("\n{} Settings Catalog Policies...", "→".cyan());
        for entry in fs::read_dir(settings_catalog_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                let policy_with_assignments: PolicyWithAssignments =
                    serde_json::from_str(&content)?;

                let name = policy_with_assignments.policy["name"]
                    .as_str()
                    .unwrap_or("Unknown");

                if args.mode == "skip-existing" && existing_policies.contains_key(name) {
                    println!("  {} Skipped (already exists): {}", "→".cyan(), name);
                    total_skipped += 1;
                    continue;
                }

                if args.dry_run {
                    println!("  {} would import: {}", "→".cyan(), name);
                } else {
                    match import_settings_catalog_policy(
                        &graph,
                        &policy_with_assignments.policy,
                        &args.mode,
                    )
                    .await
                    {
                        Ok(new_policy) => {
                            println!("  {} {}", "✓".green(), name);

                            if args.migrate_assignments
                                && !policy_with_assignments.assignments.is_empty()
                            {
                                let new_policy_id = new_policy["id"].as_str().unwrap_or("");
                                match migrate_settings_catalog_assignments(
                                    &graph,
                                    new_policy_id,
                                    &policy_with_assignments.assignments,
                                    &assignment_map,
                                    args.create_missing_groups,
                                )
                                .await
                                {
                                    Ok(migrated) => {
                                        println!("    {} {} assignments", "✓".green(), migrated)
                                    }
                                    Err(e) => println!(
                                        "    {} Assignment migration failed: {}",
                                        "✗".red(),
                                        e
                                    ),
                                }
                            }

                            total_imported += 1;
                        }
                        Err(e) => {
                            println!("  {} Failed {}: {}", "✗".red(), name, e);
                            total_errors += 1;
                        }
                    }
                }
            }
        }
    }

    // Summary
    if args.dry_run {
        println!("\n{} (no policies imported)", "DRY RUN".yellow().bold());
        println!("Would import: {} policies", total_imported);
    } else {
        println!("\n{}", "Import Summary:".cyan().bold());
        println!("  {} Imported: {}", "✓".green(), total_imported);
        if total_skipped > 0 {
            println!("  {} Skipped: {}", "→".cyan(), total_skipped);
        }
        if total_errors > 0 {
            println!("  {} Errors: {}", "✗".red(), total_errors);
        }
    }

    Ok(())
}

// Helper functions

async fn get_all_groups(client: &GraphClient) -> Result<Vec<Value>> {
    let response: Value = client.get("groups?$select=id,displayName").await?;
    Ok(response["value"].as_array().unwrap_or(&vec![]).clone())
}

async fn get_policy_assignments(
    client: &GraphClient,
    policy_id: &str,
    policy_type: &str,
    groups: &HashMap<String, String>,
) -> Result<Vec<Assignment>> {
    let endpoint = match policy_type {
        "compliance" => format!(
            "deviceManagement/deviceCompliancePolicies/{}/assignments",
            policy_id
        ),
        "deviceConfiguration" => format!(
            "deviceManagement/deviceConfigurations/{}/assignments",
            policy_id
        ),
        _ => return Ok(vec![]),
    };

    match client.get::<Value>(&endpoint).await {
        Ok(response) => {
            let mut assignments = vec![];
            if let Some(assignment_list) = response["value"].as_array() {
                for assignment in assignment_list {
                    if let Some(target) = assignment["target"].as_object() {
                        let group_id = target
                            .get("groupId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        let group_name = group_id
                            .as_ref()
                            .and_then(|id| groups.get(id))
                            .map(|n| n.clone());

                        assignments.push(Assignment {
                            id: assignment["id"].as_str().unwrap_or("").to_string(),
                            target: AssignmentTarget {
                                odata_type: target
                                    .get("@odata.type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                group_id,
                                group_name: group_name.clone(),
                                group_display_name: group_name,
                            },
                        });
                    }
                }
            }
            Ok(assignments)
        }
        Err(_) => Ok(vec![]),
    }
}

async fn list_settings_catalog_policies(client: &GraphClient) -> Result<Value> {
    client
        .get_beta("deviceManagement/configurationPolicies?$select=id,name,description,platforms,technologies")
        .await
}

async fn get_settings_catalog_policy(client: &GraphClient, policy_id: &str) -> Result<Value> {
    client
        .get_beta(&format!(
            "deviceManagement/configurationPolicies/{}",
            policy_id
        ))
        .await
}

async fn get_settings_catalog_assignments(
    client: &GraphClient,
    policy_id: &str,
    groups: &HashMap<String, String>,
) -> Result<Vec<Assignment>> {
    let endpoint = format!(
        "deviceManagement/configurationPolicies/{}/assignments",
        policy_id
    );

    match client.get_beta::<Value>(&endpoint).await {
        Ok(response) => {
            let mut assignments = vec![];
            if let Some(assignment_list) = response["value"].as_array() {
                for assignment in assignment_list {
                    if let Some(target) = assignment["target"].as_object() {
                        let group_id = target
                            .get("groupId")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());

                        let group_name = group_id
                            .as_ref()
                            .and_then(|id| groups.get(id))
                            .map(|n| n.clone());

                        assignments.push(Assignment {
                            id: assignment["id"].as_str().unwrap_or("").to_string(),
                            target: AssignmentTarget {
                                odata_type: target
                                    .get("@odata.type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                group_id,
                                group_name: group_name.clone(),
                                group_display_name: group_name,
                            },
                        });
                    }
                }
            }
            Ok(assignments)
        }
        Err(_) => Ok(vec![]),
    }
}

async fn get_existing_policy_names(client: &GraphClient) -> Result<HashMap<String, String>> {
    let mut policies = HashMap::new();

    // Get compliance policies
    if let Ok(response) = client
        .get::<Value>("deviceManagement/deviceCompliancePolicies")
        .await
    {
        if let Some(list) = response["value"].as_array() {
            for policy in list {
                if let (Some(id), Some(name)) =
                    (policy["id"].as_str(), policy["displayName"].as_str())
                {
                    policies.insert(name.to_string(), id.to_string());
                }
            }
        }
    }

    // Get device configurations
    if let Ok(response) = client
        .get::<Value>("deviceManagement/deviceConfigurations")
        .await
    {
        if let Some(list) = response["value"].as_array() {
            for policy in list {
                if let (Some(id), Some(name)) =
                    (policy["id"].as_str(), policy["displayName"].as_str())
                {
                    policies.insert(name.to_string(), id.to_string());
                }
            }
        }
    }

    // Get settings catalog (requires beta endpoint)
    if let Ok(response) = client
        .get_beta::<Value>("deviceManagement/configurationPolicies")
        .await
    {
        if let Some(list) = response["value"].as_array() {
            for policy in list {
                if let (Some(id), Some(name)) = (policy["id"].as_str(), policy["name"].as_str()) {
                    policies.insert(name.to_string(), id.to_string());
                }
            }
        }
    }

    Ok(policies)
}

async fn import_compliance_policy(
    client: &GraphClient,
    policy: &Value,
    _mode: &str,
) -> Result<Value> {
    let mut cleaned_policy = policy.clone();
    // Remove read-only properties
    if let Some(obj) = cleaned_policy.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
        obj.remove("version");
    }

    let odata_type = policy["@odata.type"].as_str().unwrap_or("");
    intune::create_policy(client, odata_type, &cleaned_policy).await
}

async fn import_device_configuration(
    client: &GraphClient,
    policy: &Value,
    _mode: &str,
) -> Result<Value> {
    let mut cleaned_policy = policy.clone();
    if let Some(obj) = cleaned_policy.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
        obj.remove("version");
    }

    let odata_type = policy["@odata.type"].as_str().unwrap_or("");
    intune::create_policy(client, odata_type, &cleaned_policy).await
}

async fn import_settings_catalog_policy(
    client: &GraphClient,
    policy: &Value,
    _mode: &str,
) -> Result<Value> {
    let mut cleaned_policy = policy.clone();
    if let Some(obj) = cleaned_policy.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
    }

    client
        .post_beta("deviceManagement/configurationPolicies", &cleaned_policy)
        .await
}

async fn migrate_policy_assignments(
    client: &GraphClient,
    policy_id: &str,
    policy_type: &str,
    source_assignments: &[Assignment],
    mapping: &HashMap<String, String>,
    create_missing: bool,
) -> Result<usize> {
    let endpoint = match policy_type {
        "compliance" => format!(
            "deviceManagement/deviceCompliancePolicies/{}/assign",
            policy_id
        ),
        "deviceConfiguration" => {
            format!("deviceManagement/deviceConfigurations/{}/assign", policy_id)
        }
        _ => return Ok(0),
    };

    let mut migrated_assignments = vec![];

    for assignment in source_assignments {
        if let Some(source_group_id) = &assignment.target.group_id {
            // Try to find mapped group
            let target_group_id = if let Some(mapped_id) = mapping.get(source_group_id) {
                Some(mapped_id.clone())
            } else if create_missing {
                // Create group with same name
                if let Some(group_name) = &assignment.target.group_name {
                    match create_group(client, group_name).await {
                        Ok(new_group) => new_group["id"].as_str().map(|s| s.to_string()),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(target_id) = target_group_id {
                migrated_assignments.push(json!({
                    "target": {
                        "@odata.type": assignment.target.odata_type,
                        "groupId": target_id
                    }
                }));
            }
        }
    }

    if !migrated_assignments.is_empty() {
        let payload = json!({
            "assignments": migrated_assignments
        });

        client.post::<Value, Value>(&endpoint, &payload).await?;
        Ok(migrated_assignments.len())
    } else {
        Ok(0)
    }
}

async fn migrate_settings_catalog_assignments(
    client: &GraphClient,
    policy_id: &str,
    source_assignments: &[Assignment],
    mapping: &HashMap<String, String>,
    create_missing: bool,
) -> Result<usize> {
    let endpoint = format!(
        "deviceManagement/configurationPolicies/{}/assign",
        policy_id
    );

    let mut migrated_assignments = vec![];

    for assignment in source_assignments {
        if let Some(source_group_id) = &assignment.target.group_id {
            let target_group_id = if let Some(mapped_id) = mapping.get(source_group_id) {
                Some(mapped_id.clone())
            } else if create_missing {
                if let Some(group_name) = &assignment.target.group_name {
                    match create_group(client, group_name).await {
                        Ok(new_group) => new_group["id"].as_str().map(|s| s.to_string()),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(target_id) = target_group_id {
                migrated_assignments.push(json!({
                    "target": {
                        "@odata.type": assignment.target.odata_type,
                        "groupId": target_id
                    }
                }));
            }
        }
    }

    if !migrated_assignments.is_empty() {
        let payload = json!({
            "assignments": migrated_assignments
        });

        client
            .post_beta::<Value, Value>(&endpoint, &payload)
            .await?;
        Ok(migrated_assignments.len())
    } else {
        Ok(0)
    }
}

async fn create_group(client: &GraphClient, group_name: &str) -> Result<Value> {
    let payload = json!({
        "displayName": group_name,
        "mailEnabled": false,
        "mailNickname": sanitize_filename(group_name),
        "securityEnabled": true
    });

    client.post("groups", &payload).await
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | ' ' => '_',
            _ => c,
        })
        .collect()
}

// Compare functionality

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// First tenant or export directory
    pub source: String,

    /// Second tenant or export directory to compare against
    pub target: String,

    /// Output format: table, json, csv
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Output file (optional)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Compare two tenants or exports
pub async fn compare(args: CompareArgs) -> Result<()> {
    println!("{} tenants/exports...", "Comparing".cyan().bold());
    println!("→ Source: {}", args.source.cyan());
    println!("→ Target: {}", args.target.cyan());

    // Check if source/target are directories (exports) or tenant names
    let source_path = PathBuf::from(&args.source);
    let target_path = PathBuf::from(&args.target);

    if source_path.is_dir() && target_path.is_dir() {
        // Compare two export directories
        compare_exports(&source_path, &target_path, &args).await?;
    } else {
        println!(
            "\n{} Live tenant comparison coming soon!",
            "ℹ".yellow().bold()
        );
        println!("Currently supports comparing export directories.");
        println!("\nTo compare tenants:");
        println!("  1. Export from source: ctl365 export export -o ./source-export");
        println!("  2. Switch tenant: ctl365 tenant switch <target>");
        println!("  3. Export from target: ctl365 export export -o ./target-export");
        println!("  4. Compare: ctl365 export compare ./source-export ./target-export");
    }

    Ok(())
}

async fn compare_exports(source: &PathBuf, target: &PathBuf, args: &CompareArgs) -> Result<()> {
    println!("\n{} Comparing export directories...", "→".cyan());

    let mut differences: Vec<(String, String, String)> = vec![]; // (policy_type, name, status)

    // Compare compliance policies
    let source_compliance = source.join("CompliancePolicies");
    let target_compliance = target.join("CompliancePolicies");

    if source_compliance.exists() {
        println!("\n{} Compliance Policies:", "→".cyan());
        compare_policy_dir(
            &source_compliance,
            &target_compliance,
            "Compliance",
            &mut differences,
        )?;
    }

    // Compare device configurations
    let source_config = source.join("DeviceConfigurations");
    let target_config = target.join("DeviceConfigurations");

    if source_config.exists() {
        println!("\n{} Device Configurations:", "→".cyan());
        compare_policy_dir(
            &source_config,
            &target_config,
            "DeviceConfig",
            &mut differences,
        )?;
    }

    // Compare settings catalog
    let source_settings = source.join("SettingsCatalog");
    let target_settings = target.join("SettingsCatalog");

    if source_settings.exists() {
        println!("\n{} Settings Catalog:", "→".cyan());
        compare_policy_dir(
            &source_settings,
            &target_settings,
            "SettingsCatalog",
            &mut differences,
        )?;
    }

    // Compare conditional access
    let source_ca = source.join("ConditionalAccess");
    let target_ca = target.join("ConditionalAccess");

    if source_ca.exists() {
        println!("\n{} Conditional Access:", "→".cyan());
        compare_policy_dir(
            &source_ca,
            &target_ca,
            "ConditionalAccess",
            &mut differences,
        )?;
    }

    // Summary
    println!("\n{}", "Comparison Summary:".cyan().bold());
    println!("────────────────────────────────────────────");

    let only_in_source: Vec<_> = differences
        .iter()
        .filter(|(_, _, s)| s == "only_in_source")
        .collect();
    let only_in_target: Vec<_> = differences
        .iter()
        .filter(|(_, _, s)| s == "only_in_target")
        .collect();
    let modified: Vec<_> = differences
        .iter()
        .filter(|(_, _, s)| s == "modified")
        .collect();

    if only_in_source.is_empty() && only_in_target.is_empty() && modified.is_empty() {
        println!("{} Exports are identical!", "✓".green().bold());
    } else {
        if !only_in_source.is_empty() {
            println!(
                "{} {} policies only in source",
                "−".red(),
                only_in_source.len()
            );
        }
        if !only_in_target.is_empty() {
            println!(
                "{} {} policies only in target",
                "+".green(),
                only_in_target.len()
            );
        }
        if !modified.is_empty() {
            println!("{} {} policies modified", "~".yellow(), modified.len());
        }
    }

    // Save to file if specified
    if let Some(output_path) = &args.output {
        let report = serde_json::json!({
            "comparison_date": chrono::Utc::now().to_rfc3339(),
            "source": args.source,
            "target": args.target,
            "differences": differences.iter().map(|(t, n, s)| {
                serde_json::json!({"type": t, "name": n, "status": s})
            }).collect::<Vec<_>>()
        });
        fs::write(output_path, serde_json::to_string_pretty(&report)?)?;
        println!(
            "\n{} Report saved to: {}",
            "✓".green(),
            output_path.display()
        );
    }

    Ok(())
}

fn compare_policy_dir(
    source_dir: &PathBuf,
    target_dir: &PathBuf,
    policy_type: &str,
    differences: &mut Vec<(String, String, String)>,
) -> Result<()> {
    use std::collections::HashSet;

    let source_files: HashSet<String> = if source_dir.exists() {
        fs::read_dir(source_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .collect()
    } else {
        HashSet::new()
    };

    let target_files: HashSet<String> = if target_dir.exists() {
        fs::read_dir(target_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .collect()
    } else {
        HashSet::new()
    };

    // Only in source
    for file in source_files.difference(&target_files) {
        let name = file.trim_end_matches(".json");
        println!("  {} {} (only in source)", "−".red(), name);
        differences.push((
            policy_type.to_string(),
            name.to_string(),
            "only_in_source".to_string(),
        ));
    }

    // Only in target
    for file in target_files.difference(&source_files) {
        let name = file.trim_end_matches(".json");
        println!("  {} {} (only in target)", "+".green(), name);
        differences.push((
            policy_type.to_string(),
            name.to_string(),
            "only_in_target".to_string(),
        ));
    }

    // In both - check for modifications
    for file in source_files.intersection(&target_files) {
        let source_content = fs::read_to_string(source_dir.join(file))?;
        let target_content = fs::read_to_string(target_dir.join(file))?;

        // Parse and compare (ignoring id and timestamps)
        let source_json: Value = serde_json::from_str(&source_content)?;
        let target_json: Value = serde_json::from_str(&target_content)?;

        if !policies_equal(&source_json, &target_json) {
            let name = file.trim_end_matches(".json");
            println!("  {} {} (modified)", "~".yellow(), name);
            differences.push((
                policy_type.to_string(),
                name.to_string(),
                "modified".to_string(),
            ));
        }
    }

    Ok(())
}

fn policies_equal(a: &Value, b: &Value) -> bool {
    // Compare policies ignoring id, createdDateTime, lastModifiedDateTime, version
    let mut a_clean = a.clone();
    let mut b_clean = b.clone();

    if let Some(obj) = a_clean.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
        obj.remove("version");
    }
    if let Some(obj) = b_clean.as_object_mut() {
        obj.remove("id");
        obj.remove("createdDateTime");
        obj.remove("lastModifiedDateTime");
        obj.remove("version");
    }

    a_clean == b_clean
}
