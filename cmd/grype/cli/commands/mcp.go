package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	mcpServer "github.com/anchore/grype/cmd/grype/cli/commands/mcp"
)

func MCP(app clio.Application) *cobra.Command {
	return &cobra.Command{
		Use:     "mcp",
		Short:   "Start an MCP (Model Context Protocol) server for Grype",
		Args:    cobra.NoArgs,
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			return mcpServer.Run(app.ID().Version)
		},
	}
}
