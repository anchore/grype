package stringutil

import "strings"

// HasAnyOfSuffixes returns an indication if the given string has any of the given suffixes.
func HasAnyOfSuffixes(input string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(input, suffix) {
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

// SplitCommaSeparatedString returns a slice of strings separated from the input string by commas
func SplitCommaSeparatedString(input string) []string {
	output := make([]string, 0)
	for _, inputItem := range strings.Split(input, ",") {
		if len(inputItem) > 0 {
			output = append(output, inputItem)
		}
	}
	return output
}
