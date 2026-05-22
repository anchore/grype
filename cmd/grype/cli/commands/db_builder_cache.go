package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

// DBBuilderCache groups the subcommands that operate on provider workspace
// tarballs (the input/output of the data-sync pipeline). These commands sit
// outside the build/pull/package phases because they move workspace data
// between hosts via tar archives — typically into and out of an OCI-hosted
// cache like ORAS-pushed ghcr.io images.
func DBBuilderCache(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage provider workspace cache archives",
		Long: `Move vulnerability provider workspace data between hosts via tar
archives. These commands are used by the data-sync pipeline to scatter
per-provider workspace state (typically backed by ORAS/ghcr.io) and gather
it on a publish host before running 'grype db-builder build'.`,
	}

	cmd.AddCommand(
		DBBuilderCacheBackup(app),
		DBBuilderCacheRestore(app),
		DBBuilderCacheStatus(app),
		DBBuilderCacheDelete(app),
	)

	return cmd
}

// readProviderNamesFromRoot lists the immediate subdirectories of root,
// each of which is the workspace for one vulnerability provider.
func readProviderNamesFromRoot(root string) ([]string, error) {
	listing, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var providers []string
	for _, f := range listing {
		if !f.IsDir() {
			continue
		}
		providers = append(providers, f.Name())
	}
	return providers, nil
}

// validateRequestedProviders intersects on-disk providers with the user's
// --provider-name filter, returning the kept set and an error if any
// requested provider is missing from disk.
func validateRequestedProviders(providersOnDisk, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return providersOnDisk, nil
	}
	requestedSet := strset.New(requested...)
	var result []string
	for _, p := range providersOnDisk {
		if requestedSet.Has(p) {
			result = append(result, p)
			requestedSet.Remove(p)
		}
	}
	if requestedSet.Size() > 0 {
		return nil, fmt.Errorf("providers requested but not present on disk: %s", strings.Join(requestedSet.List(), ", "))
	}
	return result, nil
}

// deleteProviderCache removes a single provider's workspace directory under root.
func deleteProviderCache(root, name string) error {
	workspace := dbprovider.NewWorkspace(root, name)
	dir := workspace.Path()
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		log.WithFields("dir", dir).Debug("provider cache does not exist, skipping...")
		return nil
	}
	log.WithFields("dir", dir).Info("deleting provider data")
	return os.RemoveAll(dir)
}
