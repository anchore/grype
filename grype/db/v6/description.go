package v6

import (
	"fmt"
	"path"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/internal/schemaver"
	"github.com/anchore/grype/internal/file"
)

const DescriptionFileName = "metadata.json"

type Description struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion schemaver.SchemaVer `json:"schemaVersion,omitempty"`

	// Built is the timestamp the database was built
	Built Time `json:"built"`

	// Checksum is the self-describing digest of the database file
	Checksum string `json:"checksum"`
}

type Time struct {
	time.Time
}

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", t.String())), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	str := string(data)
	if len(str) < 2 || str[0] != '"' || str[len(str)-1] != '"' {
		return fmt.Errorf("invalid time format")
	}
	str = str[1 : len(str)-1]

	parsedTime, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err
	}

	t.Time = parsedTime.In(time.UTC)
	return nil
}

func (t Time) String() string {
	return t.Time.UTC().Round(time.Second).Format(time.RFC3339)
}

func NewDescriptionFromDir(fs afero.Fs, dir string) (*Description, error) {
	// checksum the DB file
	dbFilePath := path.Join(dir, VulnerabilityDBFileName)
	digest, err := file.HashFile(fs, dbFilePath, xxhash.New64())
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum for DB file (%s): %w", dbFilePath, err)
	}
	namedDigest := fmt.Sprintf("xxh64:%s", digest)

	// access the DB to get the built time and schema version
	r, err := NewReader(Config{
		DBDirPath: dir,
	})
	if err != nil {
		return nil, err
	}

	meta, err := r.GetDBMetadata()
	if err != nil {
		return nil, err
	}

	return &Description{
		SchemaVersion: schemaver.New(meta.Model, meta.Revision, meta.Addition),
		Built:         Time{Time: *meta.BuildTimestamp},
		Checksum:      namedDigest,
	}, nil
}

func (m Description) String() string {
	return fmt.Sprintf("DB(version=%s built=%s checksum=%s)", m.SchemaVersion, m.Built, m.Checksum)
}
