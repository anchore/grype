package dbtest

import (
	"encoding/json"
	"os"
	"strings"
)

// resultIdentifier extracts the identifier field from a vunnel result JSON file.
// The identifier typically follows the format "namespace/CVE-ID" (e.g., "debian:11/CVE-2024-1234").
// Returns empty string if not found or on error.
func resultIdentifier(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var result struct {
		Identifier string `json:"identifier"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}

	return result.Identifier, nil
}

// matchesSelection checks if an identifier matches any of the selection patterns.
// If patterns is empty, returns true (include all).
func matchesSelection(identifier string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}

	for _, pattern := range patterns {
		if matchesPattern(identifier, pattern) {
			return true
		}
	}
	return false
}

// matchesPattern checks if an identifier matches a single pattern (case-insensitive).
//
// Pattern types:
//   - Full identifier (contains "/"): exact match (case-insensitive)
//     Example: "debian:10/CVE-2024-1234" matches "debian:10/cve-2024-1234"
//   - Namespace only (contains ":" but no "/"): prefix match (case-insensitive)
//     Example: "debian:10" matches "debian:10/CVE-2024-1234", "debian:10/cve-2024-5678", etc.
//   - CVE ID only (no ":" or "/"): suffix match (case-insensitive)
//     Example: "CVE-2024-1234" matches "debian:10/cve-2024-1234", "ubuntu:20.04/CVE-2024-1234", etc.
func matchesPattern(identifier, pattern string) bool {
	identifier = strings.ToLower(identifier)
	pattern = strings.ToLower(pattern)

	if strings.Contains(pattern, "/") {
		// full identifier: exact match
		return identifier == pattern
	}

	if strings.Contains(pattern, ":") {
		// namespace prefix: matches namespace/*
		return strings.HasPrefix(identifier, pattern+"/")
	}

	// CVE ID: matches */CVE-ID
	return strings.HasSuffix(identifier, "/"+pattern)
}

// filterResultFiles returns paths to result files whose identifiers match the selection patterns.
// If patterns is empty, returns all paths unchanged.
func filterResultFiles(resultPaths []string, patterns []string) []string {
	if len(patterns) == 0 {
		return resultPaths
	}

	var matched []string
	for _, path := range resultPaths {
		identifier, err := resultIdentifier(path)
		if err != nil {
			// skip files we can't parse (might be listing files or other non-result files)
			continue
		}

		if identifier == "" {
			// no identifier field, skip
			continue
		}

		if matchesSelection(identifier, patterns) {
			matched = append(matched, path)
		}
	}

	return matched
}
