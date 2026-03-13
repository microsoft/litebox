// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Trace filtering

use super::event::{ApiCategory, TraceEvent};

/// Filter rule for trace events
#[derive(Debug, Clone)]
pub enum FilterRule {
    /// Include all events
    All,
    /// Include only specific function names (exact match)
    Function(Vec<String>),
    /// Include functions matching a pattern (simple wildcard: * and ?)
    Pattern(String),
    /// Include only specific categories
    Category(Vec<ApiCategory>),
}

/// Trace filter configuration
#[derive(Debug, Clone)]
pub struct TraceFilter {
    rules: Vec<FilterRule>,
}

impl Default for TraceFilter {
    fn default() -> Self {
        Self {
            rules: vec![FilterRule::All],
        }
    }
}

impl TraceFilter {
    /// Create a new empty filter (includes all events)
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter rule
    #[must_use]
    pub fn add_rule(mut self, rule: FilterRule) -> Self {
        // If this is the first non-All rule, clear the default All rule
        if self.rules.len() == 1 && matches!(self.rules[0], FilterRule::All) {
            self.rules.clear();
        }
        self.rules.push(rule);
        self
    }

    /// Check if an event should be included based on the filter rules
    pub fn should_trace(&self, event: &TraceEvent) -> bool {
        // If no rules, include everything
        if self.rules.is_empty() {
            return true;
        }

        // Check each rule - if any rule matches, include the event
        for rule in &self.rules {
            match rule {
                FilterRule::All => return true,
                FilterRule::Function(names) => {
                    if names.iter().any(|name| name == &event.function) {
                        return true;
                    }
                }
                FilterRule::Pattern(pattern) => {
                    if matches_pattern(&event.function, pattern) {
                        return true;
                    }
                }
                FilterRule::Category(categories) => {
                    if categories.contains(&event.category) {
                        return true;
                    }
                }
            }
        }

        false
    }
}

/// Simple wildcard pattern matching (* and ? wildcards)
fn matches_pattern(text: &str, pattern: &str) -> bool {
    // Simple implementation - handle * (any chars) and ? (single char)
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    matches_pattern_recursive(&text_chars, &pattern_chars, 0, 0)
}

fn matches_pattern_recursive(text: &[char], pattern: &[char], t_idx: usize, p_idx: usize) -> bool {
    // Both exhausted - match
    if t_idx == text.len() && p_idx == pattern.len() {
        return true;
    }

    // Pattern exhausted but text remains - no match
    if p_idx == pattern.len() {
        return false;
    }

    // Handle wildcard *
    if pattern[p_idx] == '*' {
        // Try matching zero or more characters
        if matches_pattern_recursive(text, pattern, t_idx, p_idx + 1) {
            return true;
        }
        if t_idx < text.len() && matches_pattern_recursive(text, pattern, t_idx + 1, p_idx) {
            return true;
        }
        return false;
    }

    // Text exhausted but pattern has non-* - no match
    if t_idx == text.len() {
        return false;
    }

    // Handle wildcard ?
    if pattern[p_idx] == '?' {
        return matches_pattern_recursive(text, pattern, t_idx + 1, p_idx + 1);
    }

    // Handle exact character match
    if text[t_idx] == pattern[p_idx] {
        return matches_pattern_recursive(text, pattern, t_idx + 1, p_idx + 1);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("NtCreateFile", "Nt*"));
        assert!(matches_pattern("NtCreateFile", "*File"));
        assert!(matches_pattern("NtCreateFile", "Nt*File"));
        assert!(matches_pattern("NtCreateFile", "NtCreateFile"));
        assert!(!matches_pattern("NtCreateFile", "NtRead*"));

        assert!(matches_pattern("NtReadFile", "Nt????File"));
        assert!(!matches_pattern("NtReadFile", "Nt???File"));
    }

    #[test]
    fn test_filter_all() {
        let filter = TraceFilter::default();
        let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo);
        assert!(filter.should_trace(&event));
    }

    #[test]
    fn test_filter_function() {
        let filter =
            TraceFilter::new().add_rule(FilterRule::Function(vec!["NtCreateFile".to_string()]));

        let event1 = TraceEvent::call("NtCreateFile", ApiCategory::FileIo);
        let event2 = TraceEvent::call("NtReadFile", ApiCategory::FileIo);

        assert!(filter.should_trace(&event1));
        assert!(!filter.should_trace(&event2));
    }

    #[test]
    fn test_filter_pattern() {
        let filter = TraceFilter::new().add_rule(FilterRule::Pattern("Nt*File".to_string()));

        let event1 = TraceEvent::call("NtCreateFile", ApiCategory::FileIo);
        let event2 = TraceEvent::call("NtAllocateVirtualMemory", ApiCategory::Memory);

        assert!(filter.should_trace(&event1));
        assert!(!filter.should_trace(&event2));
    }

    #[test]
    fn test_filter_category() {
        let filter = TraceFilter::new().add_rule(FilterRule::Category(vec![ApiCategory::FileIo]));

        let event1 = TraceEvent::call("NtCreateFile", ApiCategory::FileIo);
        let event2 = TraceEvent::call("NtAllocateVirtualMemory", ApiCategory::Memory);

        assert!(filter.should_trace(&event1));
        assert!(!filter.should_trace(&event2));
    }
}
