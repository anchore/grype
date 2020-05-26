package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var dbClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "delete the vulnerability database",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDbClearCmd(cmd, args))
	},
}

func init() {
	dbCmd.AddCommand(dbClearCmd)
}

func runDbClearCmd(cmd *cobra.Command, args []string) int {
	log.Error("database CLEAR command...")
	return 0
}
