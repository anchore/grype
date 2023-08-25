package stringutil

import "regexp"

// MatchCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
func MatchCaptureGroups(regEx *regexp.Regexp, str string) map[string]string {
	match := regEx.FindStringSubmatch(str)
	results := make(map[string]string)
	for i, name := range regEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			results[name] = match[i]
		}
	}
	return results
}
