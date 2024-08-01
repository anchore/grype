package distribution

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/afero"
	"os"
	"path"
)

const DescriptionFileName = "metadata.json"

type DatabaseDescription struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion *int `json:"schemaVersion,omitempty"`

	// Built is the timestamp the database was built
	Built Time `json:"built"`

	// Checksum is the self-describing digest of the database file
	Checksum string `json:"checksum"`

	// Providers is a list of data provider information for data contained in the database
	Providers []ProviderInfo `json:"providers,omitempty"`
}

func ReadDatabaseDescription(fs afero.Fs, dir string) (*DatabaseDescription, error) {
	metadataFilePath := path.Join(dir, DescriptionFileName)
	exists, err := file.Exists(fs, metadataFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to check if DB metadata path exists (%s): %w", metadataFilePath, err)
	}
	if !exists {
		return nil, nil
	}
	f, err := fs.Open(metadataFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open DB metadata path (%s): %w", metadataFilePath, err)
	}
	defer f.Close()

	var m DatabaseDescription
	err = json.NewDecoder(f).Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DB metadata (%s): %w", metadataFilePath, err)
	}
	return &m, nil
}

// IsSupersededBy takes a ListingEntry and determines if the entry candidate is newer than what is hinted at
// in the current Metadata object.
func (m *DatabaseDescription) IsSupersededBy(other DatabaseDescription) bool {
	if m == nil {
		log.Debugf("cannot find existing metadata, using update...")
		// any valid update beats no database, use it!
		return true
	}

	if *other.SchemaVersion > *m.SchemaVersion {
		log.Debugf("update is a newer version than the current database, using update...")
		// the listing is newer than the existing db, use it!
		return true
	}

	if other.Built.After(m.Built.Time) {
		log.Debugf("existing database (%s) is older than candidate update (%s), using update...", m.Built.String(), other.Built.String())
		// the listing is newer than the existing db, use it!
		return true
	}

	log.Debugf("existing database is already up to date")
	return false
}

func (m DatabaseDescription) String() string {
	return fmt.Sprintf("DatabaseDescription(version=%d built=%s checksum=%s)", m.SchemaVersion, m.Built, m.Checksum)
}

// Write out a Metadata object to the given path.
func (m DatabaseDescription) Write(toPath string) error {
	if m.SchemaVersion == nil {
		return fmt.Errorf("missing schema version")
	}

	contents, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode metadata file: %w", err)
	}

	err = os.WriteFile(toPath, contents, 0600)
	if err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}
	return nil
}
