package commands

import (
	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/internal/log"
)

// DBBuilderCacheDelete removes provider workspace directories under
// --root. Without --provider-name it removes all provider data, which
// is a dev/operator convenience and not used in the standard sync flow.
func DBBuilderCacheDelete(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete provider workspace data",
		Long: `Remove provider workspace directories from --root. Without
--provider-name, removes all provider data. This is a destructive operation
intended for local development; CI sync flows do not need it.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderCacheDelete(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderCacheDelete(opts *options.DatabaseBuild) error {
	allowableProviders := strset.New(opts.Provider.IncludeFilter...)

	providerNames, err := readProviderNamesFromRoot(opts.Provider.Root)
	if err != nil {
		return err
	}

	if len(providerNames) == 0 {
		log.Info("no provider data found to delete")
		return nil
	}

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}
		if err := deleteProviderCache(opts.Provider.Root, name); err != nil {
			return err
		}
	}

	if allowableProviders.Size() == 0 {
		log.Info("all provider data deleted")
	}
	return nil
}
