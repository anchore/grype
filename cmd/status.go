package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "display general status",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runStatusCmd(cmd, args))
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatusCmd(cmd *cobra.Command, args []string) int {
	log.Error("status command...")
	return 0
}
