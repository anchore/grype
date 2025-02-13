package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	legacyDistribution "github.com/anchore/grype/grype/db/v5/distribution"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/internal/log"
)

const (
	exitCodeOnDBUpgradeAvailable = 100
)

type dbCheckOptions struct {
	Output                  string `yaml:"output" json:"output" mapstructure:"output"`
	options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
}

var _ clio.FlagAdder = (*dbCheckOptions)(nil)

func (d *dbCheckOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&d.Output, "output", "o", "format to display results (available=[text, json])")
}

func DBCheck(app clio.Application) *cobra.Command {
	opts := &dbCheckOptions{
		Output:          textOutputFormat,
		DatabaseCommand: *options.DefaultDatabaseCommand(app.ID()),
	}

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check to see if there is a database update available",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// DB commands should not opt into the low-pass check filter
			opts.DB.MaxUpdateCheckFrequency = 0
			return disableUI(app)(cmd, args)
		},
		Args: cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBCheck(*opts)
		},
	}

	// prevent from being shown in the grype config
	type configWrapper struct {
		Hidden                   *dbCheckOptions `json:"-" yaml:"-" mapstructure:"-"`
		*options.DatabaseCommand `yaml:",inline" mapstructure:",squash"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts, DatabaseCommand: &opts.DatabaseCommand})
}

func runDBCheck(opts dbCheckOptions) error {
	if opts.DatabaseCommand.Experimental.DBv6 {
		return newDBCheck(opts)
	}
	return legacyDBCheck(opts)
}

func newDBCheck(opts dbCheckOptions) error {
	client, err := distribution.NewClient(opts.ToClientConfig())
	if err != nil {
		return fmt.Errorf("unable to create distribution client: %w", err)
	}

	cfg := opts.ToCuratorConfig()

	current, err := db.ReadDescription(cfg.DBFilePath())
	if err != nil {
		log.WithFields("error", err).Debug("unable to read current database metadata")
		current = nil
	}

	archive, err := client.IsUpdateAvailable(current)
	if err != nil {
		return fmt.Errorf("unable to check for vulnerability database update: %w", err)
	}

	updateAvailable := archive != nil

	if err := presentNewDBCheck(opts.Output, os.Stdout, updateAvailable, current, archive); err != nil {
		return err
	}

	if updateAvailable {
		os.Exit(exitCodeOnDBUpgradeAvailable) //nolint:gocritic
	}
	return nil
}

type dbCheckJSON struct {
	CurrentDB       *db.Description       `json:"currentDB"`
	CandidateDB     *distribution.Archive `json:"candidateDB"`
	UpdateAvailable bool                  `json:"updateAvailable"`
}

func presentNewDBCheck(format string, writer io.Writer, updateAvailable bool, current *db.Description, candidate *distribution.Archive) error {
	switch format {
	case textOutputFormat:
		if current != nil {
			fmt.Fprintf(writer, "Installed DB version %s was built on %s\n", current.SchemaVersion, current.Built.String())
		} else {
			fmt.Fprintln(writer, "No installed DB version found")
		}

		if !updateAvailable {
			fmt.Fprintln(writer, "No update available")
			return nil
		}

		fmt.Fprintf(writer, "Updated DB version %s was built on %s\n", candidate.SchemaVersion, candidate.Built.String())
		fmt.Fprintln(writer, "You can run 'grype db update' to update to the latest db")
	case jsonOutputFormat:
		data := dbCheckJSON{
			CurrentDB:       current,
			CandidateDB:     candidate,
			UpdateAvailable: updateAvailable,
		}

		enc := json.NewEncoder(writer)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&data); err != nil {
			return fmt.Errorf("failed to db listing information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// all legacy processing below ////////////////////////////////////////////////////////////////////////////////////////

type legacyDBCheckJSON struct {
	CurrentDB       *legacyDistribution.Metadata     `json:"currentDB"`
	CandidateDB     *legacyDistribution.ListingEntry `json:"candidateDB"`
	UpdateAvailable bool                             `json:"updateAvailable"`
}

func legacyDBCheck(opts dbCheckOptions) error {
	dbCurator, err := legacyDistribution.NewCurator(opts.ToLegacyCuratorConfig())
	if err != nil {
		return err
	}

	updateAvailable, currentDBMetadata, updateDBEntry, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		return fmt.Errorf("unable to check for vulnerability database update: %+v", err)
	}

	switch opts.Output {
	case textOutputFormat:
		if currentDBMetadata != nil {
			fmt.Printf("Current DB version %d was built on %s\n", currentDBMetadata.Version, currentDBMetadata.Built.String())
		}

		if !updateAvailable {
			fmt.Println("No update available")
			return nil
		}

		fmt.Printf("Updated DB version %d was built on %s\n", updateDBEntry.Version, updateDBEntry.Built.String())
		fmt.Printf("Updated DB URL: %s\n", updateDBEntry.URL.String())
		fmt.Println("You can run 'grype db update' to update to the latest db")
	case jsonOutputFormat:
		data := legacyDBCheckJSON{
			CurrentDB:       currentDBMetadata,
			CandidateDB:     updateDBEntry,
			UpdateAvailable: updateAvailable,
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(&data); err != nil {
			return fmt.Errorf("failed to db listing information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", opts.Output)
	}

	if updateAvailable {
		os.Exit(exitCodeOnDBUpgradeAvailable) //nolint:gocritic
	}

	return nil
}
