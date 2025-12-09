//! Copilot CLI commands
//!
//! Commands for Copilot agent catalog management, search, and interaction export.

use crate::config::ConfigManager;
use crate::error::Result;
use crate::graph::copilot::{AgentQueryBuilder, CopilotClient};
use crate::graph::GraphClient;
use clap::Args;
use colored::Colorize;

// ============================================
// Agent Commands
// ============================================

#[derive(Args, Debug)]
pub struct AgentsListArgs {
    /// Filter by package type: microsoft, external, shared, custom
    #[arg(short = 't', long)]
    pub package_type: Option<String>,

    /// Show only enabled agents
    #[arg(long)]
    pub enabled: bool,

    /// Show only disabled agents
    #[arg(long)]
    pub disabled: bool,

    /// Filter by publisher name
    #[arg(short, long)]
    pub publisher: Option<String>,

    /// Maximum number of results
    #[arg(long, default_value = "50")]
    pub top: i32,

    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct AgentsGetArgs {
    /// Agent/package ID
    #[arg(short, long)]
    pub id: String,

    /// Output format: table, json
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

// ============================================
// Search Commands
// ============================================

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Search query
    #[arg(short, long)]
    pub query: String,

    /// File type filter (e.g., docx, pdf, xlsx)
    #[arg(short = 't', long)]
    pub file_type: Option<String>,

    /// Maximum number of results
    #[arg(long, default_value = "25")]
    pub top: i32,

    /// Output format: table, json
    #[arg(short, long, default_value = "table")]
    pub format: String,
}

// ============================================
// Interaction Commands
// ============================================

#[derive(Args, Debug)]
pub struct InteractionsExportArgs {
    /// Start date (ISO 8601 format, e.g., 2025-01-01)
    #[arg(long)]
    pub start: Option<String>,

    /// End date (ISO 8601 format, e.g., 2025-12-31)
    #[arg(long)]
    pub end: Option<String>,

    /// Output format: table, json
    #[arg(short, long, default_value = "json")]
    pub format: String,

    /// Output file path (optional, prints to stdout if not specified)
    #[arg(short, long)]
    pub output: Option<String>,
}

// ============================================
// Meeting Insights Commands
// ============================================

#[derive(Args, Debug)]
pub struct MeetingInsightsArgs {
    /// User ID to get meeting insights for
    #[arg(short, long)]
    pub user_id: String,

    /// Specific meeting ID (optional)
    #[arg(short, long)]
    pub meeting_id: Option<String>,

    /// Output format: table, json
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

// ============================================
// Command Implementations
// ============================================

pub async fn agents_list(args: AgentsListArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let copilot_client = CopilotClient::new(&client);

    println!(
        "{} Fetching Copilot agents from catalog...",
        "Copilot".blue().bold()
    );

    // Build query based on filters
    let mut query_builder = AgentQueryBuilder::new().top(args.top);

    if let Some(pkg_type) = &args.package_type {
        let package_type = match pkg_type.to_lowercase().as_str() {
            "microsoft" => crate::graph::copilot::AgentPackageType::Microsoft,
            "external" => crate::graph::copilot::AgentPackageType::External,
            "shared" => crate::graph::copilot::AgentPackageType::Shared,
            "custom" => crate::graph::copilot::AgentPackageType::Custom,
            _ => {
                eprintln!(
                    "{} Invalid package type '{}'. Use: microsoft, external, shared, or custom",
                    "Error:".red().bold(),
                    pkg_type
                );
                return Ok(());
            }
        };
        query_builder = query_builder.package_type(package_type);
    }

    if args.enabled {
        query_builder = query_builder.enabled_only();
    } else if args.disabled {
        query_builder = query_builder.disabled_only();
    }

    if let Some(publisher) = &args.publisher {
        query_builder = query_builder.publisher(publisher);
    }

    // Keep the query_builder for future use when the API endpoint is implemented
    let _ = query_builder;

    // For now, use the simple list method
    // In a full implementation, we'd use the query builder endpoint
    let agents = if args.package_type.is_some() || args.publisher.is_some() {
        // Use filtered query
        match args.package_type.as_deref() {
            Some("microsoft") => copilot_client.list_microsoft_agents().await?,
            Some("custom") => copilot_client.list_custom_agents().await?,
            Some("external") => copilot_client.list_external_agents().await?,
            _ => copilot_client.list_agents().await?,
        }
    } else {
        copilot_client.list_agents().await?
    };

    if agents.is_empty() {
        println!("No agents found in the catalog.");
        println!(
            "\n{} The Copilot agent catalog API is expected to be GA in December 2025.",
            "Note:".yellow()
        );
        return Ok(());
    }

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&agents)?);
        return Ok(());
    }

    println!(
        "\n{} Copilot Agents ({} found)",
        "=".repeat(60),
        agents.len()
    );
    println!(
        "{:<40} {:<15} {:<20} {}",
        "NAME".bold(),
        "TYPE".bold(),
        "PUBLISHER".bold(),
        "ENABLED".bold()
    );
    println!("{}", "-".repeat(100));

    for agent in agents {
        let name = agent.display_name.unwrap_or_else(|| "-".to_string());
        let pkg_type = agent.package_type.unwrap_or_else(|| "-".to_string());
        let publisher = agent.publisher.unwrap_or_else(|| "-".to_string());
        let enabled = match agent.is_enabled {
            Some(true) => "Yes".green().to_string(),
            Some(false) => "No".red().to_string(),
            None => "-".to_string(),
        };
        println!("{:<40} {:<15} {:<20} {}", name, pkg_type, publisher, enabled);
    }

    Ok(())
}

pub async fn agents_get(args: AgentsGetArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let copilot_client = CopilotClient::new(&client);

    println!(
        "{} Fetching agent {}...",
        "Copilot".blue().bold(),
        args.id
    );

    let agent = copilot_client.get_agent(&args.id).await?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&agent)?);
        return Ok(());
    }

    println!("\n{} Agent Details", "Copilot".blue().bold());
    println!("{}", "=".repeat(60));
    println!("  ID: {}", agent.id);
    if let Some(name) = agent.display_name {
        println!("  Name: {}", name);
    }
    if let Some(desc) = agent.description {
        println!("  Description: {}", desc);
    }
    if let Some(pkg_type) = agent.package_type {
        println!("  Package Type: {}", pkg_type);
    }
    if let Some(publisher) = agent.publisher {
        println!("  Publisher: {}", publisher);
    }
    if let Some(version) = agent.version {
        println!("  Version: {}", version);
    }
    if let Some(enabled) = agent.is_enabled {
        println!("  Enabled: {}", if enabled { "Yes" } else { "No" });
    }
    if let Some(created) = agent.created_date_time {
        println!("  Created: {}", created);
    }
    if let Some(modified) = agent.last_modified_date_time {
        println!("  Last Modified: {}", modified);
    }

    // Print manifest details if available
    if let Some(manifest) = agent.manifest {
        println!("\n  {} Manifest", "-".repeat(20));
        if let Some(name) = manifest.name {
            println!("    Name: {}", name);
        }
        if let Some(short_desc) = manifest.short_description {
            println!("    Short Description: {}", short_desc);
        }
        if let Some(full_desc) = manifest.full_description {
            println!("    Full Description: {}", full_desc);
        }
        if let Some(caps) = manifest.capabilities {
            println!("    Capabilities: {}", caps.join(", "));
        }
        if let Some(actions) = manifest.actions {
            println!("    Actions:");
            for action in actions {
                let action_name = action.name.unwrap_or_else(|| "-".to_string());
                let action_desc = action.description.unwrap_or_else(|| "-".to_string());
                println!("      - {}: {}", action_name, action_desc);
            }
        }
    }

    Ok(())
}

pub async fn search(args: SearchArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let copilot_client = CopilotClient::new(&client);

    println!(
        "{} Searching for '{}'...",
        "Copilot".blue().bold(),
        args.query
    );

    let results = copilot_client
        .search_files(&args.query, args.file_type.as_deref())
        .await?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

    // Process and display results
    let mut total_hits = 0;
    for result_set in &results.value {
        if let Some(containers) = &result_set.hits_containers {
            for container in containers {
                if let Some(hits) = &container.hits {
                    total_hits += hits.len();
                    println!(
                        "\n{} Search Results ({} found)",
                        "=".repeat(60),
                        hits.len()
                    );

                    for (i, hit) in hits.iter().enumerate() {
                        println!("\n{}. {}", i + 1, "-".repeat(50));
                        if let Some(summary) = &hit.summary {
                            println!("   Summary: {}", summary);
                        }
                        if let Some(resource) = &hit.resource {
                            if let Some(name) = resource.get("name") {
                                println!("   Name: {}", name);
                            }
                            if let Some(web_url) = resource.get("webUrl") {
                                println!("   URL: {}", web_url);
                            }
                        }
                    }
                }
            }
        }
    }

    if total_hits == 0 {
        println!("No results found.");
    }

    Ok(())
}

pub async fn interactions_export(args: InteractionsExportArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let copilot_client = CopilotClient::new(&client);

    println!(
        "{} Exporting Copilot interactions...",
        "Copilot".blue().bold()
    );

    if args.start.is_some() || args.end.is_some() {
        println!(
            "  Date range: {} to {}",
            args.start.as_deref().unwrap_or("(beginning)"),
            args.end.as_deref().unwrap_or("(now)")
        );
    }

    let interactions = copilot_client
        .export_interactions(args.start.as_deref(), args.end.as_deref())
        .await?;

    let output = if args.format == "json" {
        serde_json::to_string_pretty(&interactions)?
    } else {
        // Table format
        let mut output = String::new();
        output.push_str(&format!(
            "\n{} Copilot Interactions ({} found)\n",
            "=".repeat(60),
            interactions.len()
        ));
        output.push_str(&format!(
            "{:<40} {:<25} {:<20} {}\n",
            "ID", "CREATED", "USER", "APP"
        ));
        output.push_str(&format!("{}\n", "-".repeat(120)));

        for interaction in &interactions {
            let created = interaction
                .created_date_time
                .as_deref()
                .unwrap_or("-");
            let user = interaction.user_id.as_deref().unwrap_or("-");
            let app = interaction.app_id.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "{:<40} {:<25} {:<20} {}\n",
                interaction.id, created, user, app
            ));
        }
        output
    };

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output)?;
        println!(
            "{} Exported {} interactions to {}",
            "Success".green().bold(),
            interactions.len(),
            output_path
        );
    } else {
        println!("{}", output);
    }

    Ok(())
}

pub async fn meeting_insights(args: MeetingInsightsArgs) -> Result<()> {
    let config = ConfigManager::new()?;
    let active_tenant = config
        .get_active_tenant()?
        .ok_or_else(|| crate::error::Ctl365Error::ConfigError("No active tenant. Run 'ctl365 tenant switch <name>' first.".into()))?;
    let client = GraphClient::from_config(&config, &active_tenant.name).await?;
    let copilot_client = CopilotClient::new(&client);

    if let Some(meeting_id) = &args.meeting_id {
        println!(
            "{} Fetching insights for meeting {}...",
            "Copilot".blue().bold(),
            meeting_id
        );

        let insight = copilot_client
            .get_meeting_insight(&args.user_id, meeting_id)
            .await?;

        if args.format == "json" {
            println!("{}", serde_json::to_string_pretty(&insight)?);
        } else {
            println!("\n{} Meeting Insight", "Copilot".blue().bold());
            println!("{}", "=".repeat(60));
            println!("  ID: {}", insight.id);
            if let Some(title) = insight.title {
                println!("  Title: {}", title);
            }
            if let Some(summary) = insight.summary {
                println!("  Summary: {}", summary);
            }
            if let Some(topics) = insight.key_topics {
                println!("  Key Topics: {}", topics.join(", "));
            }
            if let Some(actions) = insight.action_items {
                println!("  Action Items:");
                for action in actions {
                    let desc = action.description.unwrap_or_else(|| "-".to_string());
                    let assigned = action.assigned_to.unwrap_or_else(|| "-".to_string());
                    println!("    - {} (assigned to: {})", desc, assigned);
                }
            }
        }
    } else {
        println!(
            "{} Fetching meeting insights for user {}...",
            "Copilot".blue().bold(),
            args.user_id
        );

        let insights = copilot_client.get_meeting_insights(&args.user_id).await?;

        if args.format == "json" {
            println!("{}", serde_json::to_string_pretty(&insights)?);
        } else {
            println!(
                "\n{} Meeting Insights ({} found)",
                "=".repeat(60),
                insights.len()
            );

            for insight in insights {
                println!("\n{}", "-".repeat(50));
                println!("  ID: {}", insight.id);
                if let Some(title) = insight.title {
                    println!("  Title: {}", title);
                }
                if let Some(summary) = insight.summary {
                    println!("  Summary: {}", summary);
                }
            }
        }
    }

    Ok(())
}
