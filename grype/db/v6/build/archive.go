package v6

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/grype/grype/db/internal/tarutil"
	"github.com/anchore/grype/grype/db/provider"
	v6 "github.com/anchore/grype/grype/db/v6"
	v6Distribution "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/internal/log"
)

func CreateArchive(dbDir, overrideArchiveExtension string, compressorCommands map[string]string) error {
	extension, err := resolveExtension(overrideArchiveExtension)
	if err != nil {
		return err
	}
	log.WithFields("from", dbDir, "extension", extension).Info("packaging database")

	cfg := v6.Config{DBDirPath: dbDir}
	r, err := v6.NewReader(cfg)
	if err != nil {
		return fmt.Errorf("unable to open vulnerability store: %w", err)
	}

	metadata, err := r.GetDBMetadata()
	if err != nil || metadata == nil {
		return fmt.Errorf("unable to get vulnerability store metadata: %w", err)
	}

	if metadata.Model != v6.ModelVersion {
		return fmt.Errorf("metadata model %d does not match vulnerability store model %d", v6.ModelVersion, metadata.Model)
	}

	providerModels, err := r.AllProviders()
	if err != nil {
		return fmt.Errorf("unable to get all providers: %w", err)
	}

	if len(providerModels) == 0 {
		return fmt.Errorf("no providers found in the vulnerability store")
	}

	eldest, err := toProviders(providerModels).EarliestTimestamp()
	if err != nil {
		return err
	}

	// output archive vulnerability-db_VERSION_OLDESTDATADATE_BUILTEPOCH.tar.gz, where:
	// - VERSION: schema version in the form of v#.#.#
	// - OLDESTDATADATE: RFC3339 formatted value (e.g. 2020-06-18T17:24:53Z) of the oldest date capture date found for all contained providers
	// - BUILTEPOCH: linux epoch formatted value of the database metadata built field
	tarName := fmt.Sprintf(
		"vulnerability-db_v%s_%s_%d.%s",
		fmt.Sprintf("%d.%d.%d", metadata.Model, metadata.Revision, metadata.Addition),
		eldest.UTC().Format(time.RFC3339),
		metadata.BuildTimestamp.Unix(),
		extension,
	)

	tarPath := filepath.Join(dbDir, tarName)
	files := []string{v6.VulnerabilityDBFileName}

	if _, err := os.Stat(path.Join(dbDir, v6.ImportMetadataFileName)); err == nil {
		files = append(files, v6.ImportMetadataFileName)
	}

	if err := populateTar(dbDir, tarName, compressorCommands, files...); err != nil {
		return err
	}

	log.WithFields("path", tarPath).Info("created database archive")

	return writeLatestDocument(tarPath, *metadata)
}

func toProviders(states []v6.Provider) provider.States {
	var result provider.States
	for _, state := range states {
		result = append(result, provider.State{
			Provider:  state.ID,
			Timestamp: *state.DateCaptured,
		})
	}
	return result
}

func resolveExtension(overrideArchiveExtension string) (string, error) {
	var extension = "tar.zst"

	if overrideArchiveExtension != "" {
		extension = strings.TrimLeft(overrideArchiveExtension, ".")
	}

	var found bool
	for _, valid := range []string{"tar.zst", "tar.xz", "tar.gz"} {
		if valid == extension {
			found = true
			break
		}
	}

	if !found {
		return "", fmt.Errorf("unsupported archive extension %q", extension)
	}
	return extension, nil
}

func populateTar(dbDir, tarName string, compressorCommands map[string]string, files ...string) error {
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get CWD: %w", err)
	}

	if dbDir != "" {
		if err = os.Chdir(dbDir); err != nil {
			return fmt.Errorf("unable to cd to build dir: %w", err)
		}

		defer func() {
			if err = os.Chdir(originalDir); err != nil {
				log.Errorf("unable to cd to original dir: %v", err)
			}
		}()
	}

	for _, f := range files {
		_, err := os.Stat(f)
		if err != nil {
			return fmt.Errorf("unable to stat file %q: %w", f, err)
		}
	}

	if err = tarutil.PopulateWithPathsAndCompressors(tarName, compressorCommands, files...); err != nil {
		return fmt.Errorf("unable to create db archive: %w", err)
	}

	return nil
}

func writeLatestDocument(tarPath string, metadata v6.DBMetadata) error {
	archive, err := v6Distribution.NewArchive(tarPath, *metadata.BuildTimestamp, metadata.Model, metadata.Revision, metadata.Addition)
	if err != nil || archive == nil {
		return fmt.Errorf("unable to create archive: %w", err)
	}

	doc := v6Distribution.NewLatestDocument(*archive)
	if doc == nil {
		return errors.New("unable to create latest document")
	}

	dbDir := filepath.Dir(tarPath)

	latestPath := path.Join(dbDir, v6Distribution.LatestFileName)

	fh, err := os.OpenFile(latestPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to create latest file: %w", err)
	}

	if err = doc.Write(fh); err != nil {
		return fmt.Errorf("unable to write latest document: %w", err)
	}
	return nil
}
