//! Named Location management for Conditional Access
//!
//! Commands for managing Named Locations (IP ranges, countries) used in CA policies.

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::{GraphClient, conditional_access};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum LocationCommands {
    /// Add a new named location (IP range or countries)
    Add(AddArgs),

    /// List all named locations
    List(ListArgs),

    /// Update a named location (change trusted status, etc.)
    Update(UpdateArgs),

    /// Remove a named location
    Remove(RemoveArgs),

    /// Create a block policy for all countries except specified ones
    Block(BlockArgs),
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Display name for the location
    #[arg(long, short = 'n')]
    pub name: String,

    /// IP address or CIDR range (e.g., 203.0.113.50/32 or 10.0.0.0/8)
    #[arg(long, conflicts_with = "countries")]
    pub ip: Option<String>,

    /// Comma-separated country codes (e.g., US,CA,GB)
    #[arg(long, conflicts_with = "ip")]
    pub countries: Option<String>,

    /// Mark IP location as trusted (for MFA bypass scenarios)
    #[arg(long)]
    pub trusted: bool,

    /// Include unknown countries/regions (for country locations)
    #[arg(long)]
    pub include_unknown: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Show detailed information
    #[arg(long, short = 'd')]
    pub detailed: bool,
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Name of the location to update
    #[arg(long, short = 'n')]
    pub name: String,

    /// Set trusted status (true/false)
    #[arg(long)]
    pub trusted: Option<bool>,

    /// New display name
    #[arg(long)]
    pub new_name: Option<String>,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Name of the location to remove
    #[arg(long, short = 'n')]
    pub name: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct BlockArgs {
    /// Country codes to ALLOW (all others will be blocked)
    #[arg(long, required = true, value_delimiter = ',')]
    pub except: Vec<String>,

    /// Custom name for the block policy (default: "Block All Countries Except ...")
    #[arg(long)]
    pub policy_name: Option<String>,

    /// Custom name for the allowed countries location
    #[arg(long)]
    pub location_name: Option<String>,

    /// Start policy in enabled mode (default: report-only)
    #[arg(long)]
    pub enable: bool,

    /// Exclusion group ID (for break-glass accounts)
    #[arg(long)]
    pub exclusion_group: Option<String>,

    /// Dry run - show what would be created
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(cmd: LocationCommands) -> Result<()> {
    match cmd {
        LocationCommands::Add(args) => add(args).await,
        LocationCommands::List(args) => list(args).await,
        LocationCommands::Update(args) => update(args).await,
        LocationCommands::Remove(args) => remove(args).await,
        LocationCommands::Block(args) => block(args).await,
    }
}

/// Add a new named location
pub async fn add(args: AddArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("{} named location...", "Creating".cyan().bold());
    println!("→ Tenant: {}", active_tenant.name.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Check if location already exists
    if let Some(existing) =
        conditional_access::find_named_location_by_name(&graph, &args.name).await?
    {
        println!(
            "{} Named location '{}' already exists (ID: {})",
            "⚠".yellow(),
            args.name.yellow(),
            existing.id
        );
        return Ok(());
    }

    let location = if let Some(ip) = &args.ip {
        // IP-based named location
        create_ip_location(&args.name, ip, args.trusted)?
    } else if let Some(countries) = &args.countries {
        // Country-based named location
        create_country_location(&args.name, countries, args.include_unknown)?
    } else {
        return Err(crate::error::Error::ConfigError(
            "Must specify either --ip or --countries".into(),
        ));
    };

    let result = conditional_access::create_named_location(&graph, &location).await?;
    let id = result["id"].as_str().unwrap_or("unknown");

    println!(
        "{} Created named location '{}' (ID: {})",
        "✓".green().bold(),
        args.name.green(),
        id
    );

    if args.ip.is_some() && args.trusted {
        println!("  {} Marked as trusted location", "→".cyan());
    }

    Ok(())
}

/// Create IP-based named location JSON
fn create_ip_location(name: &str, ip: &str, trusted: bool) -> Result<serde_json::Value> {
    // Validate CIDR format
    let cidr = if ip.contains('/') {
        ip.to_string()
    } else {
        // Single IP - add /32
        format!("{}/32", ip)
    };

    // Basic validation: must have IP part and CIDR suffix
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(crate::error::Error::ConfigError(format!(
            "Invalid CIDR format: '{}'. Expected format: x.x.x.x/prefix or IPv6/prefix",
            cidr
        )));
    }

    // Validate prefix is a number between 0-128
    let prefix: u8 = parts[1].parse().map_err(|_| {
        crate::error::Error::ConfigError(format!(
            "Invalid CIDR prefix: '{}'. Must be a number 0-128",
            parts[1]
        ))
    })?;

    // Determine if IPv4 or IPv6
    let ip_type = if cidr.contains(':') {
        if prefix > 128 {
            return Err(crate::error::Error::ConfigError(format!(
                "Invalid IPv6 prefix: {}. Must be 0-128",
                prefix
            )));
        }
        "#microsoft.graph.iPv6CidrRange"
    } else {
        if prefix > 32 {
            return Err(crate::error::Error::ConfigError(format!(
                "Invalid IPv4 prefix: {}. Must be 0-32",
                prefix
            )));
        }
        "#microsoft.graph.iPv4CidrRange"
    };

    Ok(json!({
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": name,
        "isTrusted": trusted,
        "ipRanges": [
            {
                "@odata.type": ip_type,
                "cidrAddress": cidr
            }
        ]
    }))
}

/// Valid ISO 3166-1 alpha-2 country codes supported by Microsoft Graph
const VALID_COUNTRY_CODES: &[&str] = &[
    "AF", "AX", "AL", "DZ", "AS", "AD", "AO", "AI", "AQ", "AG", "AR", "AM", "AW", "AU", "AT", "AZ",
    "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BM", "BT", "BO", "BQ", "BA", "BW", "BV", "BR",
    "IO", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV", "KY", "CF", "TD", "CL", "CN", "CX", "CC",
    "CO", "KM", "CG", "CD", "CK", "CR", "CI", "HR", "CU", "CW", "CY", "CZ", "DK", "DJ", "DM", "DO",
    "EC", "EG", "SV", "GQ", "ER", "EE", "ET", "FK", "FO", "FJ", "FI", "FR", "GF", "PF", "TF", "GA",
    "GM", "GE", "DE", "GH", "GI", "GR", "GL", "GD", "GP", "GU", "GT", "GG", "GN", "GW", "GY", "HT",
    "HM", "VA", "HN", "HK", "HU", "IS", "IN", "ID", "IR", "IQ", "IE", "IM", "IL", "IT", "JM", "JP",
    "JE", "JO", "KZ", "KE", "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY", "LI",
    "LT", "LU", "MO", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH", "MQ", "MR", "MU", "YT", "MX",
    "FM", "MD", "MC", "MN", "ME", "MS", "MA", "MZ", "MM", "NA", "NR", "NP", "NL", "NC", "NZ", "NI",
    "NE", "NG", "NU", "NF", "MP", "NO", "OM", "PK", "PW", "PS", "PA", "PG", "PY", "PE", "PH", "PN",
    "PL", "PT", "PR", "QA", "RE", "RO", "RU", "RW", "BL", "SH", "KN", "LC", "MF", "PM", "VC", "WS",
    "SM", "ST", "SA", "SN", "RS", "SC", "SL", "SG", "SX", "SK", "SI", "SB", "SO", "ZA", "GS", "SS",
    "ES", "LK", "SD", "SR", "SJ", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG", "TK",
    "TO", "TT", "TN", "TR", "TM", "TC", "TV", "UG", "UA", "AE", "GB", "US", "UM", "UY", "UZ", "VU",
    "VE", "VN", "VG", "VI", "WF", "EH", "YE", "ZM", "ZW",
];

/// Create country-based named location JSON
fn create_country_location(
    name: &str,
    countries: &str,
    include_unknown: bool,
) -> Result<serde_json::Value> {
    let country_list: Vec<String> = countries
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    if country_list.is_empty() {
        return Err(crate::error::Error::ConfigError(
            "No valid country codes provided".into(),
        ));
    }

    // Validate country codes
    let invalid: Vec<&String> = country_list
        .iter()
        .filter(|c| !VALID_COUNTRY_CODES.contains(&c.as_str()))
        .collect();

    if !invalid.is_empty() {
        return Err(crate::error::Error::ConfigError(format!(
            "Invalid country code(s): {}. Use ISO 3166-1 alpha-2 codes (e.g., US, CA, GB)",
            invalid
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(json!({
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "displayName": name,
        "countriesAndRegions": country_list,
        "includeUnknownCountriesAndRegions": include_unknown
    }))
}

/// List all named locations
pub async fn list(args: ListArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("{} named locations...", "Fetching".cyan().bold());
    println!("→ Tenant: {}", active_tenant.name.cyan());
    println!();

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;
    let locations = conditional_access::list_named_locations_typed(&graph).await?;

    if locations.is_empty() {
        println!("{}", "No named locations found.".dimmed());
        return Ok(());
    }

    println!("{}", "Named Locations:".bold());
    println!("{}", "─".repeat(60));

    for loc in &locations {
        let loc_type = if loc.odata_type.contains("ipNamedLocation") {
            "IP".cyan()
        } else if loc.odata_type.contains("countryNamedLocation") {
            "Country".yellow()
        } else {
            "Other".dimmed()
        };

        let trusted = if loc.is_trusted.unwrap_or(false) {
            " [Trusted]".green().to_string()
        } else {
            String::new()
        };

        println!(
            "  {} {} ({}){}",
            "•".cyan(),
            loc.display_name.bold(),
            loc_type,
            trusted
        );

        if args.detailed {
            println!("    ID: {}", loc.id.dimmed());

            if let Some(countries) = &loc.countries_and_regions {
                if !countries.is_empty() {
                    println!("    Countries: {}", countries.join(", ").dimmed());
                }
            }

            if let Some(ip_ranges) = &loc.ip_ranges {
                for range in ip_ranges {
                    println!("    IP Range: {}", range.cidr_address.dimmed());
                }
            }
            println!();
        }
    }

    println!("{}", "─".repeat(60));
    println!("Total: {} named locations", locations.len());

    Ok(())
}

/// Update a named location
pub async fn update(args: UpdateArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    println!("{} named location...", "Updating".cyan().bold());
    println!("→ Tenant: {}", active_tenant.name.cyan());

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Find the location
    let location = conditional_access::find_named_location_by_name(&graph, &args.name)
        .await?
        .ok_or_else(|| {
            crate::error::Error::ConfigError(format!("Named location '{}' not found", args.name))
        })?;

    // Build update payload based on location type
    let is_ip_location = location.odata_type.contains("ipNamedLocation");

    let mut update_payload = if is_ip_location {
        json!({
            "@odata.type": "#microsoft.graph.ipNamedLocation"
        })
    } else {
        json!({
            "@odata.type": "#microsoft.graph.countryNamedLocation"
        })
    };

    let mut changes = Vec::new();

    // Update trusted status (only for IP locations)
    if let Some(trusted) = args.trusted {
        if is_ip_location {
            update_payload["isTrusted"] = json!(trusted);
            changes.push(format!("trusted: {}", trusted));
        } else {
            println!(
                "{} Country locations cannot be marked as trusted",
                "⚠".yellow()
            );
        }
    }

    // Update display name
    if let Some(new_name) = &args.new_name {
        update_payload["displayName"] = json!(new_name);
        changes.push(format!("name: {}", new_name));
    }

    if changes.is_empty() {
        println!(
            "{} No changes specified. Use --trusted or --new-name",
            "⚠".yellow()
        );
        return Ok(());
    }

    // Perform the update
    graph
        .patch_no_response(
            &format!("identity/conditionalAccess/namedLocations/{}", location.id),
            &update_payload,
        )
        .await?;

    println!(
        "{} Updated named location '{}' ({})",
        "✓".green().bold(),
        args.name.green(),
        changes.join(", ")
    );

    Ok(())
}

/// Remove a named location
pub async fn remove(args: RemoveArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Find the location
    let location = conditional_access::find_named_location_by_name(&graph, &args.name)
        .await?
        .ok_or_else(|| {
            crate::error::Error::ConfigError(format!("Named location '{}' not found", args.name))
        })?;

    if !args.yes {
        println!(
            "{} Delete named location '{}'? (ID: {})",
            "⚠".yellow(),
            args.name.yellow(),
            location.id
        );
        println!("  This action cannot be undone.");
        println!("  Use --yes to skip this prompt.");
        return Ok(());
    }

    // Delete the location
    graph
        .delete(&format!(
            "identity/conditionalAccess/namedLocations/{}",
            location.id
        ))
        .await?;

    println!(
        "{} Deleted named location '{}'",
        "✓".green().bold(),
        args.name.green()
    );

    Ok(())
}

/// Create a block policy for all countries except specified ones
pub async fn block(args: BlockArgs) -> Result<()> {
    let config = ConfigManager::load()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Error::ConfigError("No active tenant".into()))?;

    let allowed_countries: Vec<String> = args
        .except
        .iter()
        .map(|s| s.trim().to_uppercase())
        .collect();

    let countries_display = allowed_countries.join(", ");

    let location_name = args
        .location_name
        .unwrap_or_else(|| format!("Allowed Countries - {}", countries_display));

    let policy_name = args
        .policy_name
        .unwrap_or_else(|| format!("Block All Countries Except {}", countries_display));

    println!("{} GeoIP block policy...", "Creating".cyan().bold());
    println!("→ Tenant: {}", active_tenant.name.cyan());
    println!("→ Allowed countries: {}", countries_display.green());
    println!("→ Location name: {}", location_name.cyan());
    println!("→ Policy name: {}", policy_name.cyan());

    if args.dry_run {
        println!();
        println!("{}", "Dry run - no changes made".yellow());
        println!();
        println!("Would create:");
        println!("  1. Named location: {}", location_name);
        println!("  2. CA policy: {}", policy_name);
        println!(
            "  3. Policy state: {}",
            if args.enable {
                "Enabled"
            } else {
                "Report-only"
            }
        );
        return Ok(());
    }

    let graph = GraphClient::from_config(&config, &active_tenant.name).await?;

    // Step 1: Create or find the allowed countries location
    let location_id =
        match conditional_access::find_named_location_by_name(&graph, &location_name).await? {
            Some(existing) => {
                println!(
                    "  {} Using existing location '{}' (ID: {})",
                    "→".cyan(),
                    location_name,
                    existing.id
                );
                existing.id
            }
            None => {
                let location = json!({
                    "@odata.type": "#microsoft.graph.countryNamedLocation",
                    "displayName": location_name,
                    "countriesAndRegions": allowed_countries,
                    "includeUnknownCountriesAndRegions": false
                });

                let result = conditional_access::create_named_location(&graph, &location).await?;
                let id = result["id"].as_str().unwrap_or("unknown").to_string();

                println!("  {} Created named location (ID: {})", "✓".green(), id);

                id
            }
        };

    // Step 2: Check if policy already exists
    if let Some(existing) = conditional_access::find_policy_by_name(&graph, &policy_name).await? {
        println!(
            "{} Policy '{}' already exists (ID: {})",
            "⚠".yellow(),
            policy_name.yellow(),
            existing.id
        );
        return Ok(());
    }

    // Step 3: Create the block policy
    let state = if args.enable {
        "enabled"
    } else {
        "enabledForReportingButNotEnforced"
    };

    let mut conditions = json!({
        "users": {
            "includeUsers": ["All"]
        },
        "applications": {
            "includeApplications": ["All"]
        },
        "locations": {
            "includeLocations": ["All"],
            "excludeLocations": [location_id]
        }
    });

    // Add exclusion group if specified
    if let Some(group_id) = &args.exclusion_group {
        conditions["users"]["excludeGroups"] = json!([group_id]);
    }

    let policy = json!({
        "displayName": policy_name,
        "state": state,
        "conditions": conditions,
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["block"]
        }
    });

    let result = conditional_access::create_policy(&graph, &policy).await?;
    let policy_id = result["id"].as_str().unwrap_or("unknown");

    println!("  {} Created CA policy (ID: {})", "✓".green(), policy_id);

    println!();
    println!(
        "{} GeoIP block policy created successfully!",
        "✓".green().bold()
    );
    println!(
        "  Policy state: {}",
        if args.enable {
            "Enabled".green().to_string()
        } else {
            "Report-only".yellow().to_string()
        }
    );

    if !args.enable {
        println!();
        println!(
            "  {} Run 'ctl365 ca enable --name \"{}\"' to enforce",
            "Tip:".cyan(),
            policy_name
        );
    }

    Ok(())
}
