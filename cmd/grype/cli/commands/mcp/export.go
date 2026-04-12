package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

func newExportTool() mcp.Tool {
	opts := append([]mcp.ToolOption{
		mcp.WithDescription(
			"Export scan results in a standard exchange format. " +
				"Use 'sarif' for CI/CD pipelines and IDEs. " +
				"Use 'cyclonedx-json' or 'cyclonedx-xml' for SBOM-based vulnerability exchange.",
		),
		mcp.WithString("output_format",
			mcp.Required(),
			mcp.Description("Export format"),
			mcp.Enum("sarif", "cyclonedx-json", "cyclonedx-xml"),
		),
	}, commonToolOptions()...)

	return mcp.NewTool("export", opts...)
}

func handleExport(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := request.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	outputFormat, err := request.RequireString("output_format")
	if err != nil {
		return mcp.NewToolResultError("output_format parameter is required"), nil
	}

	args := buildCommonArgs(request, target, outputFormat)
	return runGrype(ctx, args)
}
