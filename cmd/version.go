package cmd

import (
	"fmt"

	"github.com/anchore/vulnscan/internal"
	"github.com/spf13/cobra"
)

type Version struct {
	Version   string
	Commit    string
	BuildTime string
}

var version *Version

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the version",
	Run:   runVersionCmd,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func SetVersion(v *Version) {
	version = v
}

func runVersionCmd(cmd *cobra.Command, args []string) {
	fmt.Printf("%s %s\n", internal.ApplicationName, version.Version)
}
