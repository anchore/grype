package mcp

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func newRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]any(args),
		},
	}
}

func TestBuildCommonArgs_DefaultsOnly(t *testing.T) {
	req := newRequest(map[string]any{})
	args := buildCommonArgs(req, "alpine:latest", "table")

	assert.Equal(t, []string{"alpine:latest", "-q", "-o", "table"}, args)
}

func TestBuildCommonArgs_AllOptions(t *testing.T) {
	req := newRequest(map[string]any{
		"fail_on_severity": "high",
		"only_fixed":       true,
		"only_not_fixed":   false,
		"by_cve":           true,
		"distro":           "alpine-3.20",
		"platform":         "linux/arm64",
	})
	args := buildCommonArgs(req, "nginx:latest", "json")

	assert.Equal(t, []string{
		"nginx:latest", "-q",
		"-o", "json",
		"--fail-on", "high",
		"--only-fixed",
		"--by-cve",
		"--distro", "alpine-3.20",
		"--platform", "linux/arm64",
	}, args)
}

func TestBuildCommonArgs_OnlyNotFixed(t *testing.T) {
	req := newRequest(map[string]any{
		"only_not_fixed": true,
	})
	args := buildCommonArgs(req, "ubuntu:22.04", "table")

	assert.Equal(t, []string{
		"ubuntu:22.04", "-q",
		"-o", "table",
		"--only-notfixed",
	}, args)
}

func TestBuildCommonArgs_SBOMTarget(t *testing.T) {
	req := newRequest(map[string]any{
		"fail_on_severity": "critical",
	})
	args := buildCommonArgs(req, "sbom:./report.json", "json")

	assert.Equal(t, []string{
		"sbom:./report.json", "-q",
		"-o", "json",
		"--fail-on", "critical",
	}, args)
}

func TestBuildCommonArgs_TableFormat(t *testing.T) {
	req := newRequest(map[string]any{})
	args := buildCommonArgs(req, "alpine:latest", "table")

	assert.Equal(t, []string{"alpine:latest", "-q", "-o", "table"}, args)
}

func TestBuildCommonArgs_ExportFormats(t *testing.T) {
	for _, format := range []string{"sarif", "cyclonedx-json", "cyclonedx-xml"} {
		t.Run(format, func(t *testing.T) {
			req := newRequest(map[string]any{})
			args := buildCommonArgs(req, "alpine:latest", format)

			assert.Equal(t, []string{"alpine:latest", "-q", "-o", format}, args)
		})
	}
}
