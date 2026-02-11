package db

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/internal/tarutil"
	grypeDBLegacy "github.com/anchore/grype/grype/db/v5"
	grypeDBLegacyDistribution "github.com/anchore/grype/grype/db/v5/distribution"
	grypeDBLegacyStore "github.com/anchore/grype/grype/db/v5/store"
	"github.com/anchore/grype/internal/log"
)

// listingFiles is a set of files that should not be included in the archive
var listingFiles = strset.New("listing.json", "latest.json", "history.json")

func packageLegacyDB(dbDir, publishBaseURL, overrideArchiveExtension string, compressorCommands map[string]string) error { //nolint:funlen
	log.WithFields("from", dbDir, "url", publishBaseURL, "extension-override", overrideArchiveExtension).Info("packaging database")

	fs := afero.NewOsFs()
	metadata, err := grypeDBLegacyDistribution.NewMetadataFromDir(fs, dbDir)
	if err != nil {
		return err
	}

	if metadata == nil {
		return fmt.Errorf("no metadata found in %q", dbDir)
	}

	s, err := grypeDBLegacyStore.New(filepath.Join(dbDir, grypeDBLegacy.VulnerabilityStoreFileName), false)
	if err != nil {
		return fmt.Errorf("unable to open vulnerability store: %w", err)
	}

	id, err := s.GetID()
	if err != nil {
		return fmt.Errorf("unable to get vulnerability store ID: %w", err)
	}

	if id.SchemaVersion != metadata.Version {
		return fmt.Errorf("metadata version %d does not match vulnerability store version %d", metadata.Version, id.SchemaVersion)
	}

	u, err := url.Parse(publishBaseURL)
	if err != nil {
		return err
	}

	// we need a well-ordered string to append to the archive name to ensure uniqueness (to avoid overwriting
	// existing archives in the CDN) as well as to ensure that multiple archives created in the same day are
	// put in the correct order in the listing file. The DB timestamp represents the age of the data in the DB
	// not when the DB was created. The trailer represents the time the DB was packaged.
	trailer := fmt.Sprintf("%d", secondsSinceEpoch())

	var extension = "tar.gz"
	if overrideArchiveExtension != "" {
		extension = strings.TrimLeft(overrideArchiveExtension, ".")
	}

	var found bool
	for _, valid := range []string{"tar.zst", "tar.gz"} {
		if valid == extension {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("invalid archive extension %q", extension)
	}

	// we attach a random value at the end of the file name to prevent from overwriting DBs in S3 that are already
	// cached in the CDN. Ideally this would be based off of the archive checksum but a random string is simpler.
	tarName := fmt.Sprintf(
		"vulnerability-db_v%d_%s_%s.%s",
		metadata.Version,
		metadata.Built.Format(time.RFC3339),
		trailer,
		extension,
	)
	tarPath := path.Join(dbDir, tarName)

	if err := populateLegacyTar(tarPath, compressorCommands); err != nil {
		return err
	}

	log.WithFields("path", tarPath).Info("created database archive")

	entry, err := grypeDBLegacyDistribution.NewListingEntryFromArchive(fs, *metadata, tarPath, u)
	if err != nil {
		return fmt.Errorf("unable to create listing entry from archive: %w", err)
	}

	listing := grypeDBLegacyDistribution.NewListing(entry)
	listingPath := path.Join(dbDir, grypeDBLegacyDistribution.ListingFileName)
	if err = listing.Write(listingPath); err != nil {
		return err
	}

	log.WithFields("path", listingPath).Debug("created initial listing file")

	return nil
}

func populateLegacyTar(tarPath string, compressorCommands map[string]string) error {
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("unable to get CWD: %w", err)
	}

	dbDir, tarName := filepath.Split(tarPath)

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

	fileInfos, err := os.ReadDir("./")
	if err != nil {
		return fmt.Errorf("unable to list db directory: %w", err)
	}

	var files []string
	for _, fi := range fileInfos {
		if !listingFiles.Has(fi.Name()) && !strings.Contains(fi.Name(), ".tar.") {
			files = append(files, fi.Name())
		}
	}

	if err = tarutil.PopulateWithPathsAndCompressors(tarName, compressorCommands, files...); err != nil {
		return fmt.Errorf("unable to create db archive: %w", err)
	}

	return nil
}

func secondsSinceEpoch() int64 {
	return time.Now().UTC().Unix()
}
