package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func TestMinSeverityFailOnRemainsIndependent(t *testing.T) {
	cmd, stdout, stderr := runGrype(
		t,
		nil,
		"./testdata/sbom-grype-source.json",
		"--min-severity", "critical",
		"--fail-on", "high",
		"--output", "json",
	)

	require.Equal(t, 2, cmd.ProcessState.ExitCode(), stderr)
	assert.NotContains(t, stdout, "GHSA-pq64-v7f5-gqh8", "the known High finding should be hidden from the Critical-only report")
	assertReportSeveritiesAtOrAbove(t, stdout, vulnerability.CriticalSeverity)
}

func TestMinSeverityRejectsInvalidValuesBeforeScan(t *testing.T) {
	for _, value := range []string{"unknown", "important", " high "} {
		t.Run(value, func(t *testing.T) {
			cmd, _, stderr := runGrype(
				t,
				nil,
				"does-not-exist",
				"--min-severity", value,
			)

			require.Equal(t, 1, cmd.ProcessState.ExitCode())
			assert.Contains(t, stderr, "bad --min-severity value")
			assert.NotContains(t, stderr, "failed to catalog", "validation should fail before scanning begins")
		})
	}
}

func TestMinSeverityCLIOverridesEnvironmentAndYAML(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), ".grype.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("check-for-app-update: false\nmin-severity: low\n"), 0600))

	cmd, stdout, stderr := runGrype(
		t,
		map[string]string{"GRYPE_MIN_SEVERITY": "medium"},
		"-c", cfgPath,
		"./testdata/sbom-grype-source.json",
		"--min-severity", "critical",
		"--output", "json",
	)

	require.Equal(t, 0, cmd.ProcessState.ExitCode(), stderr)
	assert.NotContains(t, stdout, "GHSA-pq64-v7f5-gqh8", "the CLI Critical threshold should override the lower environment and YAML thresholds")
	report := parseMinSeverityReport(t, stdout)
	assert.Equal(t, "critical", report.Descriptor.Configuration.MinSeverity)
	assertReportMatchesAtOrAbove(t, report.Matches, vulnerability.CriticalSeverity)
	assertReportMatchesAtOrAbove(t, report.IgnoredMatches, vulnerability.CriticalSeverity)
}

func TestMinSeverityComposesWithFixStateFilters(t *testing.T) {
	tests := []struct {
		name          string
		flag          string
		activeIsFixed bool
	}{
		{
			name:          "only fixed",
			flag:          "--only-fixed",
			activeIsFixed: true,
		},
		{
			name:          "only not fixed",
			flag:          "--only-notfixed",
			activeIsFixed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, stdout, stderr := runGrype(
				t,
				nil,
				"./testdata/sbom-grype-source.json",
				"--min-severity", "high",
				tt.flag,
				"--output", "json",
			)

			require.Equal(t, 0, cmd.ProcessState.ExitCode(), stderr)
			report := parseMinSeverityReport(t, stdout)
			require.NotEmpty(t, report.Matches)
			require.NotEmpty(t, report.IgnoredMatches)
			assertReportMatchesAtOrAbove(t, report.Matches, vulnerability.HighSeverity)
			assertReportMatchesAtOrAbove(t, report.IgnoredMatches, vulnerability.HighSeverity)
			for _, m := range report.Matches {
				if tt.activeIsFixed {
					assert.Equal(t, string(vulnerability.FixStateFixed), m.Vulnerability.Fix.State)
				} else {
					assert.NotEqual(t, string(vulnerability.FixStateFixed), m.Vulnerability.Fix.State)
				}
			}
		})
	}
}

type minSeverityReport struct {
	Matches        []minSeverityReportMatch `json:"matches"`
	IgnoredMatches []minSeverityReportMatch `json:"ignoredMatches"`
	Descriptor     struct {
		Configuration struct {
			MinSeverity string `json:"min-severity"`
		} `json:"configuration"`
	} `json:"descriptor"`
}

type minSeverityReportMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fix      struct {
			State string `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
}

func parseMinSeverityReport(t *testing.T, output string) minSeverityReport {
	t.Helper()
	var report minSeverityReport
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	return report
}

func assertReportSeveritiesAtOrAbove(t *testing.T, output string, min vulnerability.Severity) {
	t.Helper()
	report := parseMinSeverityReport(t, output)
	assertReportMatchesAtOrAbove(t, report.Matches, min)
	assertReportMatchesAtOrAbove(t, report.IgnoredMatches, min)
}

func assertReportMatchesAtOrAbove(t *testing.T, matches []minSeverityReportMatch, min vulnerability.Severity) {
	t.Helper()
	for _, m := range matches {
		severity := vulnerability.ParseSeverity(m.Vulnerability.Severity)
		assert.GreaterOrEqual(t, severity, min, "%s has severity %s", m.Vulnerability.ID, m.Vulnerability.Severity)
	}
}
