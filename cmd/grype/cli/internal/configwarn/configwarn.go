// Package configwarn detects when grype is about to pick up a configuration
// file from the current working directory (e.g. ./.grype.yaml) without an
// explicit --config flag or GRYPE_CONFIG environment variable. Reading a
// hidden config file from the CWD silently can be a debugging hazard
// (see anchore/grype#3427), so we surface a WARN-level log when it happens.
package configwarn

import (
	"os"
	"path/filepath"
	"strings"
)

// supportedExts mirrors viper.SupportedExts. We hard-code the list rather
// than depend on viper here so this package can be used without pulling the
// configuration loader stack into tests.
var supportedExts = []string{
	"json", "toml", "yaml", "yml", "properties", "props", "prop",
	"hcl", "tfvars", "dotenv", "env", "ini",
}

// fileExists is overridable for tests.
var fileExists = func(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Detect returns the path to a CWD-resident grype config file if one would
// be picked up implicitly, otherwise it returns "".
//
// It returns "" (no warning) when:
//   - the user passed an explicit -c / --config / --config=... flag
//   - GRYPE_CONFIG (or the equivalent <appName>_CONFIG) is set
//   - no recognised config file exists in the current working directory
//
// It looks for both finder layouts that fangs uses by default:
//   - ./.<appName>.<ext>
//   - ./.<appName>/config.<ext>
func Detect(appName string, args []string, env func(string) string) string {
	if explicitConfigFlag(args) {
		return ""
	}
	envKey := strings.ToUpper(appName) + "_CONFIG"
	if env != nil && env(envKey) != "" {
		return ""
	}

	for _, ext := range supportedExts {
		candidate := "." + appName + "." + ext
		if fileExists(candidate) {
			return candidate
		}
	}
	subdir := "." + appName
	for _, ext := range supportedExts {
		candidate := filepath.Join(subdir, "config."+ext)
		if fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

// explicitConfigFlag returns true if a -c / --config flag appears in args
// (in any of: "-c file", "--config file", "-c=file", "--config=file", or
// the bundled short form "-cfoo"). We intentionally accept false positives
// here over false negatives: if anything that looks like a config flag is
// present, suppress the warning.
func explicitConfigFlag(args []string) bool {
	for i, a := range args {
		switch {
		case a == "-c", a == "--config":
			if i+1 < len(args) {
				return true
			}
		case strings.HasPrefix(a, "--config="):
			return true
		case strings.HasPrefix(a, "-c=") && len(a) > 3:
			return true
		case strings.HasPrefix(a, "-c") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			return true
		}
	}
	return false
}
