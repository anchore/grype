package internal

import "strings"

// HasAnyOfSuffixes returns an indication if the given string has any of the given suffixes.
func HasAnyOfSuffixes(input string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasSuffix(input, prefix) {
			return true
		}
	}

	return false
}

// HasAnyOfPrefixes returns an indication if the given string has any of the given prefixes.
func HasAnyOfPrefixes(input string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(input, prefix) {
			return true
		}
	}

	return false
}
