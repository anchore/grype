package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest vulnerability database",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDbUpdateCmd(cmd, args))
	},
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func runDbUpdateCmd(cmd *cobra.Command, args []string) int {
	log.Error("database UPDATE command...")
	return 0
}
