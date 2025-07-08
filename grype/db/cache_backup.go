package db

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/tarutil"
)

// TODO: this is a temporary solution so that tarutil can be migrated to grype. Ideally this would be 100% in the command package in the future

type CacheBackupConfig struct {
	ArchivePath           string
	ProviderRoot          string
	ProviderIncludeFilter []string
	ResultsOnly           bool
}

func CacheBackup(cfg CacheBackupConfig) error {
	providers := "all"
	if len(cfg.ProviderIncludeFilter) > 0 {
		providers = fmt.Sprintf("%s", cfg.ProviderIncludeFilter)
	}
	log.WithFields("providers", providers).Info("backing up provider state")

	writer, err := tarutil.NewWriter(cfg.ArchivePath)
	if err != nil {
		return fmt.Errorf("unable to create archive writer: %w", err)
	}
	defer writer.Close()

	allowableProviders := strset.New(cfg.ProviderIncludeFilter...)

	providerNames, err := readProviderNamesFromRoot(cfg.ProviderRoot)
	if err != nil {
		return err
	}

	for _, name := range providerNames {
		if allowableProviders.Size() > 0 && !allowableProviders.Has(name) {
			log.WithFields("provider", name).Trace("skipping...")
			continue
		}

		log.WithFields("provider", name).Trace("validating provider")
		workspace := provider.NewWorkspace(cfg.ProviderRoot, name)
		sd, err := workspace.ReadState()
		if err != nil {
			return fmt.Errorf("unable to read provider %q state: %w", name, err)
		}

		if err := sd.Verify(workspace.Path()); err != nil {
			return fmt.Errorf("provider %q state is invalid: %w", name, err)
		}

		log.WithFields("provider", name).Debug("archiving data")
		if err := archiveProvider(cfg, name, writer); err != nil {
			return err
		}
	}

	log.WithFields("path", cfg.ArchivePath).Info("provider state archived")

	return nil
}

func archiveProvider(cfg CacheBackupConfig, name string, writer tarutil.Writer) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	err = os.Chdir(cfg.ProviderRoot)
	if err != nil {
		return err
	}

	defer func(dir string) {
		if err := os.Chdir(dir); err != nil {
			log.Errorf("unable to restore directory: %s", err)
		}
	}(wd)

	var visitor pathVisitor
	if cfg.ResultsOnly {
		log.WithFields("provider", name).Debug("archiving results only")

		visitor = newCacheResultsOnlyWorkspaceVisitStrategy(writer, name)
	} else {
		log.WithFields("provider", name).Debug("archiving full workspace")

		visitor = cacheFullWorkspaceVisitStrategy{
			writer: writer,
		}
	}

	return filepath.Walk(name, visitor.visitPath)
}

type pathVisitor interface {
	visitPath(path string, info fs.FileInfo, err error) error
}

var (
	_ pathVisitor = (*cacheFullWorkspaceVisitStrategy)(nil)
	_ pathVisitor = (*cacheResultsOnlyWorkspaceVisitStrategy)(nil)
)

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
		// skip input data
		return nil

	case p == t.metadataPath:
		// mark metadata stale

		var state provider.State
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()

		err = json.NewDecoder(f).Decode(&state)
		if err != nil {
			return err
		}

		state.Stale = true

		// stream this to the archive
		stateJSON, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}

		return t.writer.WriteEntry(tarutil.NewEntryFromBytes(stateJSON, p, info))
	}

	return t.writer.WriteEntry(tarutil.NewEntryFromFilePath(p))
}

func readProviderNamesFromRoot(root string) ([]string, error) {
	// list all the directories in "root"
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
