package commands

import (
	"fmt"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
)

// DBBuilderPackage archives an already-built SQLite database (produced by
// 'grype db-builder build') into a compressed tarball ready for
// distribution.
func DBBuilderPackage(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "package",
		Short: "Package a built vulnerability database into an archive",
		Long: `Archive an already-built database directory (produced by
'grype db-builder build') into a compressed tarball ready for upload and
distribution. The archive extension defaults to the schema's preferred
format and can be overridden with --archive-extension.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderPackage(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderPackage(opts *options.DatabaseBuild) error {
	if opts.ArchiveExtension != "" && !strset.New("tar.gz", "tar.zst").Has(opts.ArchiveExtension) {
		return fmt.Errorf("archive-extension must be 'tar.gz' or 'tar.zst'")
	}

	// v5 DB writing (and its corresponding listing.json) is no longer supported via this command;
	// publish-base-url is intentionally omitted.
	return db.Package(opts.Dir, "", opts.ArchiveExtension, map[string]string(opts.CompressorCommands))
}
