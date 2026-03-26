//! Configuration validation edge case tests
//!
//! Tests for sanitize_tenant_name, validate_tenant_name, and related config functions.
//! These tests ensure robust handling of edge cases in tenant name processing.

use ctl365::config::{sanitize_tenant_name, validate_tenant_name};

// ============================================================================
// sanitize_tenant_name() tests
// ============================================================================

mod sanitize_tenant_name_tests {
    use super::*;

    #[test]
    fn sanitize_basic_name() {
        assert_eq!(
            sanitize_tenant_name("ACME Corp"),
            Some("acme-corp".to_string())
        );
    }

    #[test]
    fn sanitize_already_clean() {
        assert_eq!(sanitize_tenant_name("acme"), Some("acme".to_string()));
    }

    #[test]
    fn sanitize_with_special_chars() {
        // Windows invalid filename chars: <>:"/\|?*
        let result = sanitize_tenant_name("A<B>C:D");
        assert!(result.is_some());
        let sanitized = result.unwrap();
        assert!(!sanitized.contains('<'));
        assert!(!sanitized.contains('>'));
        assert!(!sanitized.contains(':'));
        assert_eq!(sanitized, "a-b-c-d");
    }

    #[test]
    fn sanitize_leading_trailing_spaces() {
        // Leading spaces become hyphens, but leading hyphens are stripped
        // Trailing spaces become hyphens, which are then trimmed
        let result = sanitize_tenant_name("  Test  ");
        assert!(result.is_some());
        let sanitized = result.unwrap();
        assert!(!sanitized.starts_with('-'));
        assert!(!sanitized.ends_with('-'));
        assert_eq!(sanitized, "test");
    }

    #[test]
    fn sanitize_multiple_hyphens() {
        let result = sanitize_tenant_name("A--B---C");
        assert!(result.is_some());
        let sanitized = result.unwrap();
        assert!(!sanitized.contains("--"));
        assert_eq!(sanitized, "a-b-c");
    }

    #[test]
    fn sanitize_empty_string() {
        assert_eq!(sanitize_tenant_name(""), None);
    }

    #[test]
    fn sanitize_only_special_chars() {
        // All characters are invalid, should return None
        assert_eq!(sanitize_tenant_name("<>:\"/\\|?*"), None);
    }

    #[test]
    fn sanitize_only_spaces() {
        // All spaces become hyphens, then stripped
        assert_eq!(sanitize_tenant_name("   "), None);
    }

    #[test]
    fn sanitize_control_chars() {
        // Control characters should be replaced with hyphens
        let result = sanitize_tenant_name("A\x00B\x1FC");
        assert!(result.is_some());
        let sanitized = result.unwrap();
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x1F'));
    }

    #[test]
    fn sanitize_preserves_unicode() {
        // Unicode letters should be preserved (just lowercased)
        let result = sanitize_tenant_name("Café");
        assert!(result.is_some());
        let sanitized = result.unwrap();
        assert!(sanitized.contains('é') || sanitized.contains("cafe")); // depends on ASCII lowercase behavior
    }

    #[test]
    fn sanitize_mixed_case() {
        assert_eq!(sanitize_tenant_name("AbCdEf"), Some("abcdef".to_string()));
    }

    #[test]
    fn sanitize_numbers() {
        assert_eq!(
            sanitize_tenant_name("Client123"),
            Some("client123".to_string())
        );
    }

    #[test]
    fn sanitize_hyphen_only() {
        // Single hyphen at start/end gets trimmed
        assert_eq!(sanitize_tenant_name("-"), None);
        assert_eq!(sanitize_tenant_name("---"), None);
    }
}

// ============================================================================
// validate_tenant_name() tests
// ============================================================================

mod validate_tenant_name_tests {
    use super::*;

    #[test]
    fn validate_normal_name() {
        assert!(validate_tenant_name("ACME").is_ok());
    }

    #[test]
    fn validate_with_spaces() {
        // Spaces in the middle are allowed
        assert!(validate_tenant_name("ACME Corp").is_ok());
    }

    #[test]
    fn validate_with_hyphens() {
        assert!(validate_tenant_name("acme-corp").is_ok());
    }

    #[test]
    fn validate_empty_name() {
        let result = validate_tenant_name("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn validate_too_long() {
        let long_name = "a".repeat(65);
        let result = validate_tenant_name(&long_name);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("64"));
    }

    #[test]
    fn validate_max_length_ok() {
        let max_name = "a".repeat(64);
        assert!(validate_tenant_name(&max_name).is_ok());
    }

    #[test]
    fn validate_leading_space() {
        let result = validate_tenant_name(" ACME");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("start"));
    }

    #[test]
    fn validate_trailing_space() {
        let result = validate_tenant_name("ACME ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("end"));
    }

    #[test]
    fn validate_leading_hyphen() {
        let result = validate_tenant_name("-ACME");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("start"));
    }

    #[test]
    fn validate_trailing_hyphen() {
        let result = validate_tenant_name("ACME-");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("end"));
    }

    #[test]
    fn validate_invalid_chars_angle_brackets() {
        let result = validate_tenant_name("A<B>C");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn validate_invalid_chars_colon() {
        let result = validate_tenant_name("A:B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_invalid_chars_quotes() {
        let result = validate_tenant_name("A\"B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_invalid_chars_backslash() {
        let result = validate_tenant_name("A\\B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_invalid_chars_pipe() {
        let result = validate_tenant_name("A|B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_invalid_chars_question() {
        let result = validate_tenant_name("A?B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_invalid_chars_asterisk() {
        let result = validate_tenant_name("A*B");
        assert!(result.is_err());
    }

    #[test]
    fn validate_control_chars() {
        let result = validate_tenant_name("A\x00B");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn validate_newline() {
        let result = validate_tenant_name("A\nB");
        assert!(result.is_err());
    }

    #[test]
    fn validate_tab() {
        let result = validate_tenant_name("A\tB");
        assert!(result.is_err());
    }

    #[test]
    fn validate_single_char() {
        assert!(validate_tenant_name("A").is_ok());
    }

    #[test]
    fn validate_numbers_only() {
        assert!(validate_tenant_name("12345").is_ok());
    }

    #[test]
    fn validate_unicode() {
        // Unicode letters should be allowed
        assert!(validate_tenant_name("Société").is_ok());
    }
}

// ============================================================================
// Integration: sanitize then validate workflow
// ============================================================================

mod sanitize_validate_workflow_tests {
    use super::*;

    #[test]
    fn sanitize_then_validate_basic() {
        let input = "ACME Corp <Test>";
        let sanitized = sanitize_tenant_name(input);
        assert!(sanitized.is_some());
        let clean = sanitized.unwrap();
        assert!(validate_tenant_name(&clean).is_ok());
    }

    #[test]
    fn sanitize_then_validate_special_chars() {
        let input = "Client: A/B\\C";
        let sanitized = sanitize_tenant_name(input);
        assert!(sanitized.is_some());
        let clean = sanitized.unwrap();
        // Sanitized name should pass validation
        assert!(validate_tenant_name(&clean).is_ok());
        // And should not contain any of the special chars
        assert!(!clean.contains(':'));
        assert!(!clean.contains('/'));
        assert!(!clean.contains('\\'));
    }

    #[test]
    fn sanitize_produces_valid_names() {
        // Various edge case inputs
        let inputs = vec![
            "Test Company",
            "ACME (US)",
            "Client #1",
            "Test & Demo",
            "résumé",
            "123 Corp",
        ];

        for input in inputs {
            if let Some(sanitized) = sanitize_tenant_name(input) {
                assert!(
                    validate_tenant_name(&sanitized).is_ok(),
                    "Sanitized '{}' -> '{}' should be valid",
                    input,
                    sanitized
                );
            }
        }
    }
}

// ============================================================================
// Boundary tests
// ============================================================================

mod boundary_tests {
    use super::*;

    #[test]
    fn validate_exactly_64_chars() {
        let name = "a".repeat(64);
        assert!(validate_tenant_name(&name).is_ok());
    }

    #[test]
    fn validate_exactly_65_chars() {
        let name = "a".repeat(65);
        assert!(validate_tenant_name(&name).is_err());
    }

    #[test]
    fn validate_very_long_name() {
        let name = "a".repeat(1000);
        assert!(validate_tenant_name(&name).is_err());
    }

    #[test]
    fn sanitize_very_long_name() {
        // Sanitize should work on long names (doesn't truncate)
        let name = "A".repeat(100);
        let result = sanitize_tenant_name(&name);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 100);
    }
}
