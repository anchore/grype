package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/tarutil"
)

// DBBuilderCacheBackup creates a compressed tar archive of one or more
// provider workspaces. The data-sync workflow uploads the resulting archive
// to ORAS/ghcr.io so it can be restored on a publish host before
// 'db-builder build'.
func DBBuilderCacheBackup(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Archive provider workspace data into a cache tarball",
		Long: `Walk the provider workspace under --root and write a compressed tar
archive at --path containing the selected providers' state. By default the
archive includes both 'input' and 'results' directories; pass --results-only
to omit raw input data (and mark each provider's metadata as stale so the
next pull is forced to re-download).`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderCacheBackup(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderCacheBackup(opts *options.DatabaseBuild) error {
	if opts.Cache.Path == "" {
		return fmt.Errorf("--path is required")
	}

	providersDescr := "all"
	if len(opts.Provider.IncludeFilter) > 0 {
		providersDescr = fmt.Sprintf("%s", opts.Provider.IncludeFilter)
	}
	log.WithFields("providers", providersDescr).Info("backing up provider state")

	writer, err := tarutil.NewWriter(opts.Cache.Path)
	if err != nil {
		return fmt.Errorf("unable to create archive writer: %w", err)
	}
	defer writer.Close()

	allowableProviders := strset.New(opts.Provider.IncludeFilter...)

	providerNames, err := readProviderNamesFromRoot(opts.Provider.Root)
	if err != nil {
		return err
	}

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

		log.WithFields("provider", name).Trace("validating provider")
		workspace := dbprovider.NewWorkspace(opts.Provider.Root, name)
		sd, err := workspace.ReadState()
		if err != nil {
			return fmt.Errorf("unable to read provider %q state: %w", name, err)
		}

		if err := sd.Verify(workspace.Path()); err != nil {
			return fmt.Errorf("provider %q state is invalid: %w", name, err)
		}

		log.WithFields("provider", name).Debug("archiving data")
		if err := archiveProvider(opts, name, writer); err != nil {
			return err
		}
	}

	log.WithFields("path", opts.Cache.Path).Info("provider state archived")
	return nil
}

func archiveProvider(opts *options.DatabaseBuild, name string, writer tarutil.Writer) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	if err := os.Chdir(opts.Provider.Root); err != nil {
		return err
	}
	defer func(dir string) {
		if err := os.Chdir(dir); err != nil {
			log.Errorf("unable to restore directory: %w", err)
		}
	}(wd)

	var visitor pathVisitor
	if opts.Cache.ResultsOnly {
		log.WithFields("provider", name).Debug("archiving results only")
		visitor = newCacheResultsOnlyWorkspaceVisitStrategy(writer, name)
	} else {
		log.WithFields("provider", name).Debug("archiving full workspace")
		visitor = cacheFullWorkspaceVisitStrategy{writer: writer}
	}

	return filepath.Walk(name, visitor.visitPath)
}

type pathVisitor interface {
	visitPath(path string, info fs.FileInfo, err error) error
}

type cacheFullWorkspaceVisitStrategy struct {
	writer tarutil.Writer
}

func (t cacheFullWorkspaceVisitStrategy) visitPath(p string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	return t.writer.WriteEntry(tarutil.NewEntryFromFilePath(p))
}

type cacheResultsOnlyWorkspaceVisitStrategy struct {
	writer       tarutil.Writer
	providerName string
	metadataPath string
	inputPath    string
}

func newCacheResultsOnlyWorkspaceVisitStrategy(writer tarutil.Writer, providerName string) cacheResultsOnlyWorkspaceVisitStrategy {
	return cacheResultsOnlyWorkspaceVisitStrategy{
		writer:       writer,
		providerName: providerName,
		metadataPath: filepath.Join(providerName, "metadata.json"),
		inputPath:    filepath.Join(providerName, "input"),
	}
}

func (t cacheResultsOnlyWorkspaceVisitStrategy) visitPath(p string, info fs.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}

	switch {
	case strings.HasPrefix(p, t.inputPath):
		return nil
	case p == t.metadataPath:
		var state dbprovider.State
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&state); err != nil {
			return err
		}

		state.Stale = true

		stateJSON, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}

		return t.writer.WriteEntry(tarutil.NewEntryFromBytes(stateJSON, p, info))
	}

	return t.writer.WriteEntry(tarutil.NewEntryFromFilePath(p))
}
