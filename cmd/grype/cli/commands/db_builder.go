package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

// DBBuilder is the parent command for all DB-producing operations: running
// vulnerability providers (vunnel), writing the SQLite database from the
// resulting workspace, and packaging the database into a distributable
// archive. End-user "consume an existing DB" commands live under `grype db`.
func DBBuilder(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db-builder",
		Short: "Build and manage vulnerability database artifacts",
		Long: `Build vulnerability databases from upstream sources.

This command group produces vulnerability databases from provider data
(typically vunnel), writes them to SQLite, and packages them for
distribution. The canonical flow is:

  grype db-builder pull -p <name>            # refresh one provider workspace via vunnel
  grype db-builder build --dir ./build       # write a DB from the workspace
  grype db-builder package --dir ./build     # archive the DB

For commands that operate on an already-installed database (check, update,
search, ...), see 'grype db' instead.`,
	}

	cmd.AddCommand(
		DBBuilderPull(app),
		DBBuilderBuild(app),
		DBBuilderPackage(app),
	)

	return cmd
}
