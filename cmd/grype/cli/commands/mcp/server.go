package mcp

import (
	"github.com/mark3labs/mcp-go/server"
)

// Run starts an MCP server over stdio that exposes grype scanning as a tool.
func Run(version string) error {
	s := server.NewMCPServer(
		"grype",
		version,
		server.WithToolCapabilities(false),
	)

	s.AddTool(newScanTool(), handleScan)
	s.AddTool(newAnalyzeTool(), handleAnalyze)
	s.AddTool(newExportTool(), handleExport)

	return server.ServeStdio(s)
}
