package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var dbCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "check to see if there is a database update available",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runDbCheckCmd(cmd, args))
	},
}

func init() {
	dbCmd.AddCommand(dbCheckCmd)
}

func runDbCheckCmd(cmd *cobra.Command, args []string) int {
	log.Error("database CHECK command...")
	return 0
}
