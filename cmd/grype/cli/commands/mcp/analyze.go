package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

func newAnalyzeTool() mcp.Tool {
	opts := append([]mcp.ToolOption{
		mcp.WithDescription(
			"Deep vulnerability analysis returning full JSON details including vulnerability descriptions, " +
				"CVSS scores, EPSS scores, CWEs, KEV (known exploited) data, advisory URLs, fix versions, " +
				"and match details. Use when investigating or reasoning about vulnerabilities.",
		),
	}, commonToolOptions()...)

	return mcp.NewTool("analyze", opts...)
}

func handleAnalyze(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := request.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	args := buildCommonArgs(request, target, "json")
	return runGrype(ctx, args)
}
