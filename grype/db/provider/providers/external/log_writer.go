package external

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/internal/log"
)

var (
	logLevelPattern = regexp.MustCompile(`^(?P<prefix>.*)\[(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR)\s?\] (?P<suffix>.*)$`)

	// The provider logging level can be independently controlled via vunnel config,
	// so the default if no log level could be parsed should be info
	defaultLogLevel = "INFO"
)

type logWriter struct {
	name string
}

func newLogWriter(name string) *logWriter {
	return &logWriter{
		name: name,
	}
}

// MatchNamedCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
// This is only for the first match in the regex. Callers shouldn't be providing regexes with multiple capture groups with the same name.
func matchNamedCaptureGroups(regEx *regexp.Regexp, content string) map[string]string {
	// note: we are looking across all matches and stopping on the first non-empty match. Why? Take the following example:
	// input: "cool something to match against" pattern: `((?P<name>match) (?P<version>against))?`. Since the pattern is
	// encapsulated in an optional capture group, there will be results for each character, but the results will match
	// on nothing. The only "true" match will be at the end ("match against").
	allMatches := regEx.FindAllStringSubmatch(content, -1)
	var results map[string]string
	for _, match := range allMatches {
		// fill a candidate results map with named capture group results, accepting empty values, but not groups with
		// no names
		for nameIdx, name := range regEx.SubexpNames() {
			if nameIdx > len(match) || len(name) == 0 {
				continue
			}
			if results == nil {
				results = make(map[string]string)
			}
			results[name] = match[nameIdx]
		}
		// note: since we are looking for the first best potential match we should stop when we find the first one
		// with non-empty results.
		if !isEmptyMap(results) {
			break
		}
	}
	return results
}

func isEmptyMap(m map[string]string) bool {
	if len(m) == 0 {
		return true
	}
	for _, value := range m {
		if value != "" {
			return false
		}
	}
	return true
}

func processLogLine(line string) (string, string) {
	line = strings.TrimRight(line, "\n")
	groups := matchNamedCaptureGroups(logLevelPattern, line)

	level, ok := groups["level"]
	if !ok || level == "" {
		return defaultLogLevel, line
	}

	prefix, ok := groups["prefix"]
	if !ok {
		return defaultLogLevel, line
	}

	suffix, ok := groups["suffix"]
	if !ok {
		return defaultLogLevel, line
	}

	message := fmt.Sprintf("%s%s", prefix, suffix)
	return strings.ToUpper(level), message
}

func (lw logWriter) Write(p []byte) (n int, err error) {
	for _, line := range strings.Split(string(p), "\n") {
		level, line := processLogLine(line)
		if line != "" {
			message := fmt.Sprintf("[%s]", lw.name) + line

			switch level {
			case "TRACE":
				log.Trace(message)
			case "DEBUG":
				log.Debug(message)
			case "INFO":
				log.Info(message)
			case "WARN", "WARNING":
				log.Warn(message)
			case "ERROR":
				log.Error(message)
			default:
				log.Info(message)
			}
		}
	}

	return len(p), nil
}
