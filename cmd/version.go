package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	v1 "github.com/anchore/grype-db/pkg/db/v1"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
	"github.com/spf13/cobra"
)

var outputFormat string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the version",
	Run:   printVersion,
}

func init() {
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "format to show version information (available=[text, json])")

	rootCmd.AddCommand(versionCmd)
}

func printVersion(_ *cobra.Command, _ []string) {
	versionInfo := version.FromBuild()
	switch outputFormat {
	case "text":
		fmt.Println("Application:         ", internal.ApplicationName)
		fmt.Println("Version:             ", versionInfo.Version)
		fmt.Println("BuildDate:           ", versionInfo.BuildDate)
		fmt.Println("GitCommit:           ", versionInfo.GitCommit)
		fmt.Println("GitTreeState:        ", versionInfo.GitTreeState)
		fmt.Println("Platform:            ", versionInfo.Platform)
		fmt.Println("GoVersion:           ", versionInfo.GoVersion)
		fmt.Println("Compiler:            ", versionInfo.Compiler)
		fmt.Println("Supported DB Schema: ", v1.SchemaVersion)
	case "json":

		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		err := enc.Encode(&struct {
			version.Version
			Application   string `json:"application"`
			SchemaVersion int    `json:"supportedDbSchema"`
		}{
			Version:       versionInfo,
			Application:   internal.ApplicationName,
			SchemaVersion: v1.SchemaVersion,
		})
		if err != nil {
			fmt.Printf("failed to show version information: %+v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("unsupported output format: %s\n", outputFormat)
		os.Exit(1)
	}
}
