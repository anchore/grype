package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	grypeFormat "github.com/anchore/grype/internal/format"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	syftSource "github.com/anchore/syft/syft/source"
)

func TestMinSeverityFilteredDocumentIsSharedByAllOutputs(t *testing.T) {
	doc := newReportFilterTestDocument(t, []string{"Unknown", "Low", "High", "Critical"})
	filterDocumentByMinSeverity(&doc, severityPointer(vulnerability.HighSeverity))

	outputs := writeReportOutputs(t, doc)

	for format, output := range outputs {
		t.Run(format, func(t *testing.T) {
			assert.NotContains(t, output, "CVE-0-unknown")
			assert.NotContains(t, output, "CVE-1-low")
			assert.Contains(t, output, "CVE-2-high")
			assert.Contains(t, output, "CVE-3-critical")
		})
	}

	assert.Contains(t, outputs["table"], "suppressed by VEX")
	assert.Contains(t, outputs["template"], "ignored:CVE-2-high")
	assert.Contains(t, outputs["template"], "ignored:CVE-3-critical")
	assertValidJSONReportMetadata(t, outputs["json"])
	assertValidSARIFStructure(t, outputs["sarif"])
	assertValidCycloneDXMetadata(t, outputs["cyclonedx-json"])
}

func TestMinSeverityFullyFilteredDocumentProducesValidEmptyOutputs(t *testing.T) {
	doc := newReportFilterTestDocument(t, []string{"Unknown", "Low"})
	filterDocumentByMinSeverity(&doc, severityPointer(vulnerability.CriticalSeverity))

	outputs := writeReportOutputs(t, doc)

	assert.Contains(t, outputs["table"], "No vulnerabilities found")
	assert.Empty(t, strings.TrimSpace(outputs["template"]))

	var jsonReport map[string]any
	require.NoError(t, json.Unmarshal([]byte(outputs["json"]), &jsonReport))
	matches, ok := jsonReport["matches"].([]any)
	require.True(t, ok, "JSON matches should be an array")
	assert.Empty(t, matches)
	assert.NotNil(t, jsonReport["source"])
	assert.NotNil(t, jsonReport["descriptor"])

	var sarifReport map[string]any
	require.NoError(t, json.Unmarshal([]byte(outputs["sarif"]), &sarifReport))
	runs, ok := sarifReport["runs"].([]any)
	require.True(t, ok)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)
	assert.NotNil(t, run["tool"])
	results, ok := run["results"].([]any)
	require.True(t, ok)
	assert.Empty(t, results)

	var cyclonedxReport map[string]any
	require.NoError(t, json.Unmarshal([]byte(outputs["cyclonedx-json"]), &cyclonedxReport))
	assert.NotNil(t, cyclonedxReport["metadata"])
	if rawVulnerabilities, exists := cyclonedxReport["vulnerabilities"]; exists {
		vulnerabilities, ok := rawVulnerabilities.([]any)
		require.True(t, ok)
		assert.Empty(t, vulnerabilities)
	}
}

func writeReportOutputs(t *testing.T, doc models.Document) map[string]string {
	t.Helper()

	dir := t.TempDir()
	templatePath := filepath.Join(dir, "report.tmpl")
	templateContents := "{{range .Matches}}match:{{.Vulnerability.ID}}\n{{end}}{{range .IgnoredMatches}}ignored:{{.Vulnerability.ID}}\n{{end}}"
	require.NoError(t, os.WriteFile(templatePath, []byte(templateContents), 0600))

	formats := []string{"table", "json", "sarif", "template", "cyclonedx-json"}
	paths := make(map[string]string, len(formats))
	outputOptions := make([]string, 0, len(formats))
	for _, format := range formats {
		path := filepath.Join(dir, strings.ReplaceAll(format, "-", "_")+".out")
		paths[format] = path
		outputOptions = append(outputOptions, format+"="+path)
	}

	writer, err := grypeFormat.MakeScanResultWriter(outputOptions, "", grypeFormat.PresentationConfig{
		TemplateFilePath: templatePath,
		ShowSuppressed:   true,
	})
	require.NoError(t, err)

	sourceDescription := syftSource.Description{
		Name:     "test-source",
		Version:  "1.0.0",
		Metadata: syftSource.DirectoryMetadata{Path: "/test/source"},
	}
	reportPackage := syftPkg.Package{
		Name:    "component",
		Version: "1.0.0",
		Type:    syftPkg.NpmPkg,
		PURL:    "pkg:npm/component@1.0.0",
	}
	reportPackage.SetID()
	reportSBOM := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: syftPkg.NewCollection(reportPackage),
		},
		Source: sourceDescription,
	}
	require.NoError(t, writer.Write(models.PresenterConfig{
		ID:       clio.Identification{Name: "grype", Version: "test"},
		Document: doc,
		SBOM:     reportSBOM,
	}))

	outputs := make(map[string]string, len(paths))
	for format, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		outputs[format] = string(contents)
	}
	return outputs
}

func assertValidJSONReportMetadata(t *testing.T, output string) {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	assert.NotNil(t, report["source"])
	assert.NotNil(t, report["distro"])
	assert.NotNil(t, report["descriptor"])
	assert.NotNil(t, report["alertsByPackage"])
}

func assertValidSARIFStructure(t *testing.T, output string) {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	runs, ok := report["runs"].([]any)
	require.True(t, ok)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)
	assert.NotNil(t, run["tool"])
}

func assertValidCycloneDXMetadata(t *testing.T, output string) {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &report))
	assert.NotNil(t, report["metadata"])
	assert.NotNil(t, report["components"])
}
