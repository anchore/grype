package db

import (
	"os"
	"path/filepath"

	grypeDBLegacyDistribution "github.com/anchore/grype/internal/db/v5/distribution"
	v6process "github.com/anchore/grype/internal/db/v6/data"
)

func Package(dbDir, publishBaseURL, overrideArchiveExtension string) error {
	// check if metadata file exists, if so, then this
	if _, err := os.Stat(filepath.Join(dbDir, grypeDBLegacyDistribution.MetadataFileName)); os.IsNotExist(err) {
		// TODO: detect from disk which version of the DB is present
		return v6process.CreateArchive(dbDir, overrideArchiveExtension)
	}
	return packageLegacyDB(dbDir, publishBaseURL, overrideArchiveExtension)
}
