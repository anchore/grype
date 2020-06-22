package db

import (
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/anchore/vulnscan/internal/file"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/hashicorp/go-version"
	"github.com/spf13/afero"
)

const metadataFileName = "metadata.json"

type Metadata struct {
	Built    time.Time
	Version  *version.Version
	Checksum string
}

type MetadataJSON struct {
	Built    string `json:"built"` // RFC 3339
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
}

func (m MetadataJSON) ToMetadata() (Metadata, error) {
	build, err := time.Parse(time.RFC3339, m.Built)
	if err != nil {
		return Metadata{}, fmt.Errorf("cannot convert built time (%s): %+v", m.Built, err)
	}

	ver, err := version.NewVersion(m.Version)
	if err != nil {
		return Metadata{}, fmt.Errorf("cannot parse version (%s): %+v", m.Version, err)
	}

	metadata := Metadata{
		Built:    build.UTC(),
		Version:  ver,
		Checksum: m.Checksum,
	}

	return metadata, nil
}

func metadataPath(dir string) string {
	return path.Join(dir, metadataFileName)
}

func newMetadataFromDir(fs afero.Fs, dir string) (*Metadata, error) {
	metadataFilePath := metadataPath(dir)
	if !file.Exists(fs, metadataFilePath) {
		return nil, nil
	}
	f, err := fs.Open(metadataFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open DB metadata path (%s): %w", metadataFilePath, err)
	}
	defer f.Close()

	var m Metadata
	err = json.NewDecoder(f).Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DB metadata (%s): %w", metadataFilePath, err)
	}
	return &m, nil
}

func (m *Metadata) UnmarshalJSON(data []byte) error {
	var mj MetadataJSON
	if err := json.Unmarshal(data, &mj); err != nil {
		return err
	}
	me, err := mj.ToMetadata()
	if err != nil {
		return err
	}
	*m = me
	return nil
}

func (m *Metadata) isSupercededBy(entry *ListingEntry) bool {
	if m == nil {
		log.Debugf("cannot find existing metadata, using update...")
		// any valid update beats no database, use it!
		return true
	}

	if entry.Version.GreaterThan(m.Version) {
		log.Debugf("update is a newer version than the current database, using update...")
		// the listing is newer than the existing db, use it!
		return true
	}

	if entry.Built.After(m.Built) {
		log.Debugf("existing database (%s) is older than candidate update (%s), using update...", m.Built.String(), entry.Built.String())
		// the listing is newer than the existing db, use it!
		return true
	}

	log.Debugf("existing database is already up to date")
	return false
}

func (m Metadata) String() string {
	return fmt.Sprintf("Metadata(built=%s version=%s checksum=%s)", m.Built, m.Version, m.Checksum)
}
