package cmd

import (
	"github.com/spf13/cobra"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "operate on the result cache",
}

func init() {
	rootCmd.AddCommand(cacheCmd)
}
