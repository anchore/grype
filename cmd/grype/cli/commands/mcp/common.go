package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
)

func commonToolOptions() []mcp.ToolOption {
	return []mcp.ToolOption{
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The scan target: image reference (e.g. alpine:latest), directory (dir:path/), SBOM file (sbom:path.json), PURL, or CPE"),
		),
		mcp.WithString("fail_on_severity",
			mcp.Description("Flag when vulnerabilities meet or exceed this severity — results are still returned"),
			mcp.Enum("negligible", "low", "medium", "high", "critical"),
		),
		mcp.WithBoolean("only_fixed",
			mcp.Description("Only show vulnerabilities that have a known fix"),
		),
		mcp.WithBoolean("only_not_fixed",
			mcp.Description("Only show vulnerabilities that do not have a known fix"),
		),
		mcp.WithBoolean("by_cve",
			mcp.Description("Group results by CVE ID instead of vendor-specific advisory IDs"),
		),
		mcp.WithString("distro",
			mcp.Description("Override distro when scanning directories or SBOMs where it cannot be auto-detected (e.g. alpine-3.20)"),
		),
		mcp.WithString("platform",
			mcp.Description("Specify architecture for multi-architecture images (e.g. linux/arm64)"),
		),
	}
}

func buildCommonArgs(request mcp.CallToolRequest, target string, outputFormat string) []string {
	args := []string{target, "-q", "-o", outputFormat}

	if failOn := request.GetString("fail_on_severity", ""); failOn != "" {
		args = append(args, "--fail-on", failOn)
	}

	if request.GetBool("only_fixed", false) {
		args = append(args, "--only-fixed")
	}

	if request.GetBool("only_not_fixed", false) {
		args = append(args, "--only-notfixed")
	}

	if request.GetBool("by_cve", false) {
		args = append(args, "--by-cve")
	}

	if distro := request.GetString("distro", ""); distro != "" {
		args = append(args, "--distro", distro)
	}

	if platform := request.GetString("platform", ""); platform != "" {
		args = append(args, "--platform", platform)
	}

	return args
}

func runGrype(ctx context.Context, args []string) (*mcp.CallToolResult, error) {
	grypeBin, err := grypeExecutable()
	if err != nil {
		return mcp.NewToolResultErrorFromErr("failed to determine grype executable path", err), nil
	}

	cmd := exec.CommandContext(ctx, grypeBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		// Exit code 2 means vulnerabilities exceeded the --fail-on severity threshold.
		// The scan output is still valid in this case.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			// valid output — fall through
		} else {
			return mcp.NewToolResultError(
				fmt.Sprintf("grype scan failed: %v\nstderr: %s", err, stderr.String()),
			), nil
		}
	}

	return mcp.NewToolResultText(stdout.String()), nil
}

func grypeExecutable() (string, error) {
	return os.Executable()
}
