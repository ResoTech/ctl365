//! Viva CLI commands
//!
//! Commands for Viva Engage communities, role management, and Connections configuration.

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::viva::{CommunityPrivacy, VivaClient, VivaRole};
use crate::graph::GraphClient;
use clap::Args;
use colored::Colorize;

// ============================================
// Community Commands
// ============================================

#[derive(Args, Debug)]
pub struct CommunityCreateArgs {
    /// Community display name
    #[arg(short, long)]
    pub name: String,

    /// Community description
    #[arg(short, long)]
    pub description: Option<String>,

    /// Privacy setting: public or private
    #[arg(short, long, default_value = "public")]
    pub privacy: String,

    /// Owner user IDs (comma-separated)
    #[arg(short, long)]
    pub owners: Option<String>,

    /// Dry run - show what would be created without creating
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct CommunityListArgs {
    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct CommunityDeleteArgs {
    /// Community ID to delete
    #[arg(short, long)]
    pub id: String,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct CommunityMemberArgs {
    /// Community ID
    #[arg(short, long)]
    pub community_id: String,

    /// User ID to add/remove
    #[arg(short, long)]
    pub user_id: String,

    /// Dry run - show what would be changed without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ============================================
// Role Commands
// ============================================

#[derive(Args, Debug)]
pub struct RoleAssignArgs {
    /// User ID or UPN to assign the role to
    #[arg(short, long)]
    pub user_id: String,

    /// Role to assign: network-admin, verified-admin, corporate-communicator, answers-admin
    #[arg(short, long)]
    pub role: String,

    /// Dry run - show what would be assigned without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct RoleListArgs {
    /// Role to list assignments for (optional, lists all if not specified)
    #[arg(short, long)]
    pub role: Option<String>,

    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct RoleRevokeArgs {
    /// Role assignment ID to revoke
    #[arg(short, long)]
    pub assignment_id: String,

    /// Dry run - show what would be revoked without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ============================================
// Connections Commands
// ============================================

#[derive(Args, Debug)]
pub struct ConnectionsHomeSiteArgs {
    /// Site URL to set as home site (omit to show current)
    #[arg(short, long)]
    pub site_url: Option<String>,

    /// Dry run - show what would be changed without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// ============================================
// Command Implementations
// ============================================

fn parse_role(role_str: &str) -> Option<VivaRole> {
    match role_str.to_lowercase().replace('-', "").as_str() {
        "networkadmin" | "networkadministrator" => Some(VivaRole::NetworkAdmin),
        "verifiedadmin" | "verifiedadministrator" => Some(VivaRole::VerifiedAdmin),
        "corporatecommunicator" | "corpcommunicator" => Some(VivaRole::CorporateCommunicator),
        "answersadmin" | "answersadministrator" => Some(VivaRole::AnswersAdmin),
        _ => None,
    }
}

pub async fn community_create(args: CommunityCreateArgs) -> Result<()> {
    let privacy = match args.privacy.to_lowercase().as_str() {
        "public" => CommunityPrivacy::Public,
        "private" => CommunityPrivacy::Private,
        _ => {
            eprintln!(
                "{} Invalid privacy setting '{}'. Use: public or private",
                "Error:".red().bold(),
                args.privacy
            );
            return Ok(());
        }
    };

    println!(
        "{} Creating Viva Engage community '{}'...",
        "Viva".magenta().bold(),
        args.name
    );

    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("  Display Name: {}", args.name);
        if let Some(desc) = &args.description {
            println!("  Description: {}", desc);
        }
        println!("  Privacy: {:?}", privacy);
        if let Some(owners) = &args.owners {
            println!("  Owners: {}", owners);
        }
        return Ok(());
    }

    if !args.yes {
        println!("\nThis will create a new Viva Engage community.");
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    let owner_ids = args
        .owners
        .map(|o| o.split(',').map(|s| s.trim().to_string()).collect());

    let community = viva_client
        .create_community(&args.name, args.description.as_deref(), privacy, owner_ids)
        .await?;

    println!(
        "\n{} Community created successfully!",
        "Success".green().bold()
    );
    println!("  ID: {}", community.id);
    if let Some(url) = community.web_url {
        println!("  URL: {}", url);
    }
    if let Some(group_id) = community.group_id {
        println!("  M365 Group ID: {}", group_id);
    }

    Ok(())
}

pub async fn community_list(args: CommunityListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!("{} Fetching Viva Engage communities...", "Viva".magenta().bold());

    let communities = viva_client.list_communities().await?;

    if communities.is_empty() {
        println!("No communities found.");
        return Ok(());
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&communities)?);
        return Ok(());
    }

    println!(
        "\n{} Viva Engage Communities ({} found)",
        "=".repeat(60),
        communities.len()
    );
    println!(
        "{:<40} {:<15} {}",
        "NAME".bold(),
        "PRIVACY".bold(),
        "ID".bold()
    );
    println!("{}", "-".repeat(100));

    for community in communities {
        let name = community.display_name.unwrap_or_else(|| "-".to_string());
        let privacy = community.privacy.unwrap_or_else(|| "-".to_string());
        println!("{:<40} {:<15} {}", name, privacy, community.id);
    }

    Ok(())
}

pub async fn community_delete(args: CommunityDeleteArgs) -> Result<()> {
    if !args.yes {
        println!(
            "{} This will permanently delete the community.",
            "Warning:".yellow().bold()
        );
        print!("Type 'DELETE' to confirm: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "DELETE" {
            println!("Aborted.");
            return Ok(());
        }
    }

    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!(
        "{} Deleting community {}...",
        "Viva".magenta().bold(),
        args.id
    );
    viva_client.delete_community(&args.id).await?;

    println!(
        "{} Community deleted successfully!",
        "Success".green().bold()
    );

    Ok(())
}

pub async fn community_add_member(args: CommunityMemberArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would add member:", "→".cyan());
        println!("  Community ID: {}", args.community_id);
        println!("  User ID: {}", args.user_id);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!("\nThis will add user {} to community {}.", args.user_id, args.community_id);
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!(
        "{} Adding user {} to community {}...",
        "Viva".magenta().bold(),
        args.user_id,
        args.community_id
    );

    viva_client
        .add_community_member(&args.community_id, &args.user_id)
        .await?;

    println!("{} Member added successfully!", "Success".green().bold());

    Ok(())
}

pub async fn community_remove_member(args: CommunityMemberArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would remove member:", "→".cyan());
        println!("  Community ID: {}", args.community_id);
        println!("  User ID: {}", args.user_id);
        return Ok(());
    }

    // Confirmation prompt
    if !args.yes {
        println!("\nThis will remove user {} from community {}.", args.user_id, args.community_id);
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!(
        "{} Removing user {} from community {}...",
        "Viva".magenta().bold(),
        args.user_id,
        args.community_id
    );

    viva_client
        .remove_community_member(&args.community_id, &args.user_id)
        .await?;

    println!("{} Member removed successfully!", "Success".green().bold());

    Ok(())
}

pub async fn role_assign(args: RoleAssignArgs) -> Result<()> {
    let role = match parse_role(&args.role) {
        Some(r) => r,
        None => {
            eprintln!(
                "{} Invalid role '{}'. Use: network-admin, verified-admin, corporate-communicator, or answers-admin",
                "Error:".red().bold(),
                args.role
            );
            return Ok(());
        }
    };

    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would assign role:", "→".cyan());
        println!("  User ID: {}", args.user_id);
        println!("  Role: {}", role.display_name());
        return Ok(());
    }

    if !args.yes {
        println!(
            "{} This will assign the {} role to user {}.",
            "Warning:".yellow().bold(),
            role.display_name(),
            args.user_id
        );
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!(
        "{} Assigning {} role to user {}...",
        "Viva".magenta().bold(),
        role.display_name(),
        args.user_id
    );

    let assignment = viva_client.assign_role(&args.user_id, role).await?;

    println!("{} Role assigned successfully!", "Success".green().bold());
    println!("  Assignment ID: {}", assignment.id);

    Ok(())
}

pub async fn role_list(args: RoleListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    let roles_to_query = if let Some(role_str) = &args.role {
        match parse_role(role_str) {
            Some(r) => vec![r],
            None => {
                eprintln!(
                    "{} Invalid role '{}'. Use: network-admin, verified-admin, corporate-communicator, or answers-admin",
                    "Error:".red().bold(),
                    role_str
                );
                return Ok(());
            }
        }
    } else {
        vec![
            VivaRole::NetworkAdmin,
            VivaRole::VerifiedAdmin,
            VivaRole::CorporateCommunicator,
            VivaRole::AnswersAdmin,
        ]
    };

    println!("{} Fetching role assignments...", "Viva".magenta().bold());

    for role in roles_to_query {
        let assignments = viva_client.list_role_assignments(role).await?;

        if args.format == "json" {
            println!("{}", serde_json::to_string_pretty(&assignments)?);
            continue;
        }

        println!(
            "\n{} {} ({} assignments)",
            "=".repeat(40),
            role.display_name(),
            assignments.len()
        );

        if assignments.is_empty() {
            println!("  No assignments found.");
            continue;
        }

        println!("{:<50} {}", "PRINCIPAL ID".bold(), "ASSIGNMENT ID".bold());
        println!("{}", "-".repeat(90));

        for assignment in assignments {
            let assignment_id = assignment.id.unwrap_or_else(|| "-".to_string());
            println!("{:<50} {}", assignment.principal_id, assignment_id);
        }
    }

    Ok(())
}

pub async fn role_revoke(args: RoleRevokeArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    // Dry run mode
    if args.dry_run {
        println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
        println!("{} Would revoke assignment: {}", "→".cyan(), args.assignment_id);
        return Ok(());
    }

    if !args.yes {
        println!(
            "{} This will revoke the role assignment.",
            "Warning:".yellow().bold()
        );
        print!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let viva_client = VivaClient::new(&client);

    println!(
        "{} Revoking role assignment {}...",
        "Viva".magenta().bold(),
        args.assignment_id
    );

    viva_client.revoke_role(&args.assignment_id).await?;

    println!("{} Role revoked successfully!", "Success".green().bold());

    Ok(())
}

pub async fn connections_home_site(args: ConnectionsHomeSiteArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;

    println!("→ Active tenant: {}", active_tenant.name.cyan().bold());

    if let Some(site_url) = args.site_url {
        // Dry run mode
        if args.dry_run {
            println!("\n{}", "DRY RUN - No changes will be made".yellow().bold());
            println!("{} Would set home site to: {}", "→".cyan(), site_url);
            return Ok(());
        }

        // Confirmation prompt
        if !args.yes {
            println!("\nThis will set the Viva Connections home site to: {}", site_url);
            print!("Continue? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let client = GraphClient::from_config(&config, &active_tenant.name).await?;
        let viva_client = VivaClient::new(&client);

        println!(
            "{} Setting home site to {}...",
            "Viva Connections".magenta().bold(),
            site_url
        );
        viva_client.set_home_site(&site_url).await?;
        println!("{} Home site updated successfully!", "Success".green().bold());
    } else {
        let client = GraphClient::from_config(&config, &active_tenant.name).await?;
        let viva_client = VivaClient::new(&client);

        println!(
            "{} Fetching current home site configuration...",
            "Viva Connections".magenta().bold()
        );
        let settings = viva_client.get_home_site().await?;
        println!("\n{}", serde_json::to_string_pretty(&settings)?);
    }

    Ok(())
}
