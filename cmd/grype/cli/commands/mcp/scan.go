package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

func newScanTool() mcp.Tool {
	opts := append([]mcp.ToolOption{
		mcp.WithDescription(
			"Quick vulnerability scan returning a compact summary table with package names, " +
				"installed/fixed versions, vulnerability IDs, severity, EPSS scores, and risk scores. " +
				"Best for a fast overview of what is vulnerable.",
		),
	}, commonToolOptions()...)

	return mcp.NewTool("scan", opts...)
}

func handleScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := request.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target parameter is required"), nil
	}

	args := buildCommonArgs(request, target, "table")
	return runGrype(ctx, args)
}
