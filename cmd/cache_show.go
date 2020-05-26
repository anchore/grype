package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var cacheShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show images that have been scanned",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runCacheShowCmd(cmd, args))
	},
}

func init() {
	cacheCmd.AddCommand(cacheShowCmd)
}

func runCacheShowCmd(cmd *cobra.Command, args []string) int {
	log.Error("cache SHOW command...")
	return 0
}
