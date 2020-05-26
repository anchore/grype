package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "delete the results cache",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(runCacheClearCmd(cmd, args))
	},
}

func init() {
	cacheCmd.AddCommand(cacheClearCmd)
}

func runCacheClearCmd(cmd *cobra.Command, args []string) int {
	log.Error("cache CLEAR command...")
	return 0
}
