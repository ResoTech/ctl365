//! Professional HTML Report Template for Resolve Technology
//!
//! Generates branded HTML reports for:
//! - Tenant audits and compliance
//! - Configuration change logs
//! - Security assessments
//! - Executive summaries

use chrono::{DateTime, Local};
use serde::Serialize;

/// Report metadata
#[derive(Debug, Clone, Serialize)]
pub struct ReportMetadata {
    pub title: String,
    pub tenant_name: String,
    pub tenant_id: String,
    pub generated_at: DateTime<Local>,
    pub generated_by: String,
    pub report_type: ReportType,
}

#[derive(Debug, Clone, Serialize)]
pub enum ReportType {
    Compliance,
    Security,
    Configuration,
    Executive,
    ChangeLog,
    Audit,
}

impl ReportType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportType::Compliance => "Compliance Report",
            ReportType::Security => "Security Assessment",
            ReportType::Configuration => "Configuration Report",
            ReportType::Executive => "Executive Summary",
            ReportType::ChangeLog => "Change Log",
            ReportType::Audit => "Audit Report",
        }
    }
}

/// Compliance score section
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceScore {
    pub overall_score: u8,
    pub grade: String,
    pub categories: Vec<CategoryScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryScore {
    pub name: String,
    pub score: u8,
    pub passed: u32,
    pub total: u32,
    pub status: String,
}

/// Finding for audit reports
#[derive(Debug, Clone, Serialize)]
pub struct ReportFinding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub current_value: Option<String>,
    pub expected_value: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::Critical => "#dc2626",
            Severity::High => "#ea580c",
            Severity::Medium => "#ca8a04",
            Severity::Low => "#2563eb",
            Severity::Info => "#6b7280",
        }
    }
}

/// Configuration change entry
#[derive(Debug, Clone, Serialize)]
pub struct ConfigChange {
    pub timestamp: DateTime<Local>,
    pub category: String,
    pub setting: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub changed_by: String,
}

/// Generate the complete HTML report
pub fn generate_html_report(
    metadata: &ReportMetadata,
    compliance: Option<&ComplianceScore>,
    findings: &[ReportFinding],
    changes: &[ConfigChange],
    summary_sections: &[(String, String)],
) -> String {
    let css = get_css_styles();
    let header = generate_header(metadata);
    let compliance_section = compliance
        .map(generate_compliance_section)
        .unwrap_or_default();
    let findings_section = generate_findings_section(findings);
    let changes_section = generate_changes_section(changes);
    let summary_section = generate_summary_sections(summary_sections);
    let footer = generate_footer(metadata);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - {tenant}</title>
    <style>
{css}
    </style>
</head>
<body>
    <div class="container">
{header}
{compliance_section}
{summary_section}
{findings_section}
{changes_section}
{footer}
    </div>
</body>
</html>"#,
        title = metadata.title,
        tenant = metadata.tenant_name,
        css = css,
        header = header,
        compliance_section = compliance_section,
        summary_section = summary_section,
        findings_section = findings_section,
        changes_section = changes_section,
        footer = footer,
    )
}

fn get_css_styles() -> &'static str {
    r#"
        :root {
            --primary: #1e40af;
            --primary-dark: #1e3a8a;
            --secondary: #64748b;
            --success: #16a34a;
            --warning: #ca8a04;
            --danger: #dc2626;
            --info: #0284c7;
            --light: #f8fafc;
            --dark: #1e293b;
            --border: #e2e8f0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
            color: var(--dark);
            background: var(--light);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: white;
            min-height: 100vh;
        }

        /* Header */
        .header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 3px solid var(--primary);
            margin-bottom: 2rem;
        }

        .logo {
            max-width: 200px;
            height: auto;
            margin-bottom: 1.5rem;
        }

        .header h1 {
            color: var(--primary);
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            color: var(--secondary);
            font-size: 1.1rem;
        }

        .header .metadata {
            display: flex;
            justify-content: center;
            gap: 2rem;
            margin-top: 1rem;
            font-size: 0.9rem;
            color: var(--secondary);
        }

        /* Compliance Score */
        .compliance-section {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }

        .score-display {
            text-align: center;
            margin-bottom: 1.5rem;
        }

        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255,255,255,0.2);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .score-grade {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .category-scores {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .category-card {
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: 8px;
        }

        .category-name {
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .category-bar {
            height: 8px;
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
            overflow: hidden;
        }

        .category-bar-fill {
            height: 100%;
            background: white;
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .category-stats {
            font-size: 0.85rem;
            margin-top: 0.5rem;
            opacity: 0.9;
        }

        /* Sections */
        .section {
            margin-bottom: 2rem;
        }

        .section-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border);
        }

        /* Findings */
        .finding {
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }

        .finding.critical { border-left-color: #dc2626; }
        .finding.high { border-left-color: #ea580c; }
        .finding.medium { border-left-color: #ca8a04; }
        .finding.low { border-left-color: #2563eb; }
        .finding.info { border-left-color: #6b7280; }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }

        .finding-title {
            font-weight: 600;
            font-size: 1rem;
        }

        .finding-severity {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }

        .severity-critical { background: #dc2626; }
        .severity-high { background: #ea580c; }
        .severity-medium { background: #ca8a04; }
        .severity-low { background: #2563eb; }
        .severity-info { background: #6b7280; }

        .finding-category {
            font-size: 0.85rem;
            color: var(--secondary);
            margin-bottom: 0.5rem;
        }

        .finding-description {
            margin-bottom: 0.75rem;
        }

        .finding-details {
            background: var(--light);
            padding: 0.75rem;
            border-radius: 6px;
            font-size: 0.9rem;
        }

        .finding-detail-row {
            display: flex;
            margin-bottom: 0.25rem;
        }

        .finding-detail-label {
            font-weight: 600;
            width: 120px;
            flex-shrink: 0;
        }

        /* Changes Table */
        .changes-table {
            width: 100%;
            border-collapse: collapse;
        }

        .changes-table th,
        .changes-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        .changes-table th {
            background: var(--light);
            font-weight: 600;
            color: var(--secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .changes-table tr:hover {
            background: var(--light);
        }

        .change-old {
            color: #dc2626;
            text-decoration: line-through;
        }

        .change-new {
            color: #16a34a;
            font-weight: 500;
        }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }

        .summary-card {
            background: var(--light);
            padding: 1.25rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }

        .summary-card h4 {
            font-size: 0.9rem;
            color: var(--secondary);
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }

        .summary-card p {
            font-size: 1rem;
            color: var(--dark);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--secondary);
            font-size: 0.85rem;
        }

        .footer-brand {
            font-weight: 600;
            color: var(--primary);
        }

        /* Print Styles */
        @media print {
            body {
                background: white;
            }
            .container {
                padding: 0;
                max-width: none;
            }
            .finding,
            .summary-card {
                break-inside: avoid;
            }
        }
    "#
}

fn generate_header(metadata: &ReportMetadata) -> String {
    format!(
        r#"        <header class="header">
            <img src="assets/logo/reso.png" alt="Resolve Technology" class="logo" onerror="this.style.display='none'">
            <h1>{title}</h1>
            <p class="subtitle">{report_type}</p>
            <div class="metadata">
                <span><strong>Tenant:</strong> {tenant}</span>
                <span><strong>Generated:</strong> {date}</span>
                <span><strong>By:</strong> {by}</span>
            </div>
        </header>"#,
        title = metadata.title,
        report_type = metadata.report_type.as_str(),
        tenant = metadata.tenant_name,
        date = metadata.generated_at.format("%Y-%m-%d %H:%M:%S"),
        by = metadata.generated_by,
    )
}

fn generate_compliance_section(score: &ComplianceScore) -> String {
    let categories_html: String = score
        .categories
        .iter()
        .map(|cat| {
            format!(
                r#"                <div class="category-card">
                    <div class="category-name">{name}</div>
                    <div class="category-bar">
                        <div class="category-bar-fill" style="width: {score}%"></div>
                    </div>
                    <div class="category-stats">{passed}/{total} controls passed ({score}%)</div>
                </div>"#,
                name = cat.name,
                score = cat.score,
                passed = cat.passed,
                total = cat.total,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"        <section class="compliance-section">
            <div class="score-display">
                <div class="score-circle">{score}</div>
                <div class="score-grade">Grade: {grade}</div>
            </div>
            <div class="category-scores">
{categories}
            </div>
        </section>"#,
        score = score.overall_score,
        grade = score.grade,
        categories = categories_html,
    )
}

fn generate_findings_section(findings: &[ReportFinding]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let findings_html: String = findings
        .iter()
        .map(|f| {
            let severity_class = match f.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };

            let details = if f.current_value.is_some() || f.expected_value.is_some() {
                let current = f
                    .current_value
                    .as_ref()
                    .map(|v| {
                        format!(
                            r#"<div class="finding-detail-row"><span class="finding-detail-label">Current:</span> {}</div>"#,
                            v
                        )
                    })
                    .unwrap_or_default();
                let expected = f
                    .expected_value
                    .as_ref()
                    .map(|v| {
                        format!(
                            r#"<div class="finding-detail-row"><span class="finding-detail-label">Expected:</span> {}</div>"#,
                            v
                        )
                    })
                    .unwrap_or_default();
                format!(
                    r#"<div class="finding-details">{}{}</div>"#,
                    current, expected
                )
            } else {
                String::new()
            };

            format!(
                r#"            <div class="finding {class}">
                <div class="finding-header">
                    <span class="finding-title">{title}</span>
                    <span class="finding-severity severity-{class}">{severity}</span>
                </div>
                <div class="finding-category">{category}</div>
                <p class="finding-description">{description}</p>
                {details}
                <p class="finding-description"><strong>Recommendation:</strong> {recommendation}</p>
            </div>"#,
                class = severity_class,
                title = f.title,
                severity = f.severity.as_str(),
                category = f.category,
                description = f.description,
                details = details,
                recommendation = f.recommendation,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"        <section class="section">
            <h2 class="section-title">Findings ({count})</h2>
{findings}
        </section>"#,
        count = findings.len(),
        findings = findings_html,
    )
}

fn generate_changes_section(changes: &[ConfigChange]) -> String {
    if changes.is_empty() {
        return String::new();
    }

    let rows: String = changes
        .iter()
        .map(|c| {
            let old_value = c
                .old_value
                .as_ref()
                .map(|v| format!(r#"<span class="change-old">{}</span> → "#, v))
                .unwrap_or_default();

            format!(
                r#"                <tr>
                    <td>{timestamp}</td>
                    <td>{category}</td>
                    <td>{setting}</td>
                    <td>{old}<span class="change-new">{new}</span></td>
                    <td>{by}</td>
                </tr>"#,
                timestamp = c.timestamp.format("%Y-%m-%d %H:%M"),
                category = c.category,
                setting = c.setting,
                old = old_value,
                new = c.new_value,
                by = c.changed_by,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"        <section class="section">
            <h2 class="section-title">Configuration Changes ({count})</h2>
            <table class="changes-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Category</th>
                        <th>Setting</th>
                        <th>Change</th>
                        <th>Changed By</th>
                    </tr>
                </thead>
                <tbody>
{rows}
                </tbody>
            </table>
        </section>"#,
        count = changes.len(),
        rows = rows,
    )
}

fn generate_summary_sections(sections: &[(String, String)]) -> String {
    if sections.is_empty() {
        return String::new();
    }

    let cards: String = sections
        .iter()
        .map(|(title, content)| {
            format!(
                r#"            <div class="summary-card">
                <h4>{title}</h4>
                <p>{content}</p>
            </div>"#,
                title = title,
                content = content,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"        <section class="section">
            <h2 class="section-title">Summary</h2>
            <div class="summary-grid">
{cards}
            </div>
        </section>"#,
        cards = cards,
    )
}

fn generate_footer(metadata: &ReportMetadata) -> String {
    format!(
        r#"        <footer class="footer">
            <p>Report generated by <span class="footer-brand">CTL365</span> for <span class="footer-brand">Resolve Technology</span></p>
            <p>Tenant: {tenant} ({tenant_id})</p>
            <p>Generated: {date}</p>
            <p>&copy; {year} Resolve Technology LLC. All rights reserved.</p>
        </footer>"#,
        tenant = metadata.tenant_name,
        tenant_id = metadata.tenant_id,
        date = metadata.generated_at.format("%Y-%m-%d %H:%M:%S %Z"),
        year = metadata.generated_at.format("%Y"),
    )
}

/// Calculate grade from score
pub fn score_to_grade(score: u8) -> String {
    match score {
        90..=100 => "A".to_string(),
        80..=89 => "B".to_string(),
        70..=79 => "C".to_string(),
        60..=69 => "D".to_string(),
        _ => "F".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_to_grade() {
        assert_eq!(score_to_grade(95), "A");
        assert_eq!(score_to_grade(85), "B");
        assert_eq!(score_to_grade(75), "C");
        assert_eq!(score_to_grade(65), "D");
        assert_eq!(score_to_grade(50), "F");
    }

    #[test]
    fn test_severity_colors() {
        assert_eq!(Severity::Critical.color(), "#dc2626");
        assert_eq!(Severity::High.color(), "#ea580c");
        assert_eq!(Severity::Medium.color(), "#ca8a04");
    }

    #[test]
    fn test_report_type_as_str() {
        assert_eq!(ReportType::Compliance.as_str(), "Compliance Report");
        assert_eq!(ReportType::Security.as_str(), "Security Assessment");
        assert_eq!(ReportType::Executive.as_str(), "Executive Summary");
    }

    #[test]
    fn test_generate_html_report() {
        let metadata = ReportMetadata {
            title: "Test Report".to_string(),
            tenant_name: "Test Tenant".to_string(),
            tenant_id: "test-tenant-id".to_string(),
            generated_at: Local::now(),
            generated_by: "ctl365".to_string(),
            report_type: ReportType::Audit,
        };

        let html = generate_html_report(&metadata, None, &[], &[], &[]);

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Report"));
        assert!(html.contains("Test Tenant"));
        assert!(html.contains("Resolve Technology"));
    }

    #[test]
    fn test_generate_with_compliance_score() {
        let metadata = ReportMetadata {
            title: "Compliance Check".to_string(),
            tenant_name: "Client Corp".to_string(),
            tenant_id: "client-id".to_string(),
            generated_at: Local::now(),
            generated_by: "admin".to_string(),
            report_type: ReportType::Compliance,
        };

        let compliance = ComplianceScore {
            overall_score: 85,
            grade: "B".to_string(),
            categories: vec![CategoryScore {
                name: "Security".to_string(),
                score: 90,
                passed: 9,
                total: 10,
                status: "Good".to_string(),
            }],
        };

        let html = generate_html_report(&metadata, Some(&compliance), &[], &[], &[]);

        assert!(html.contains("85"));
        assert!(html.contains("Grade: B"));
        assert!(html.contains("Security"));
    }

    #[test]
    fn test_generate_with_findings() {
        let metadata = ReportMetadata {
            title: "Security Audit".to_string(),
            tenant_name: "Acme Inc".to_string(),
            tenant_id: "acme-id".to_string(),
            generated_at: Local::now(),
            generated_by: "auditor".to_string(),
            report_type: ReportType::Security,
        };

        let findings = vec![ReportFinding {
            severity: Severity::High,
            category: "Authentication".to_string(),
            title: "MFA Not Enabled".to_string(),
            description: "Multi-factor authentication is not enabled for all users.".to_string(),
            recommendation: "Enable MFA for all users via Conditional Access.".to_string(),
            current_value: Some("Disabled".to_string()),
            expected_value: Some("Enabled".to_string()),
        }];

        let html = generate_html_report(&metadata, None, &findings, &[], &[]);

        assert!(html.contains("MFA Not Enabled"));
        assert!(html.contains("High"));
        assert!(html.contains("Authentication"));
    }
}
