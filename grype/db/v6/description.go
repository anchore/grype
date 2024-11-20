package v6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/internal/schemaver"
	"github.com/anchore/grype/internal/file"
)

const ChecksumFileName = VulnerabilityDBFileName + ".checksum"

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

func ReadDescription(dir string) (*Description, error) {
	dbFilePath := filepath.Join(dir, VulnerabilityDBFileName)

	// check if exists
	if _, err := os.Stat(dbFilePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("database does not exist")
		}
		return nil, fmt.Errorf("failed to access database file: %w", err)
	}

	desc, err := newPartialDescriptionFromDB(dbFilePath)
	if err != nil {
		return nil, err
	}

	// read checksums file value
	checksum, err := ReadDBChecksum(dir)
	if err != nil {
		return nil, err
	}

	desc.Checksum = checksum

	return desc, nil
}

func ReadDBChecksum(dir string) (string, error) {
	checksumsFilePath := filepath.Join(dir, ChecksumFileName)
	checksums, err := os.ReadFile(checksumsFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read checksums file: %w", err)
	}

	if len(checksums) == 0 {
		return "", fmt.Errorf("checksums file is empty")
	}

	if !bytes.HasPrefix(checksums, []byte("xxh64:")) {
		return "", fmt.Errorf("checksums file is not in the expected format")
	}

	return string(checksums), nil
}

func CalculateDescription(dbFilePath string) (*Description, error) {
	desc, err := newPartialDescriptionFromDB(dbFilePath)
	if err != nil {
		return nil, err
	}

	namedDigest, err := CalculateDigest(dbFilePath)
	if err != nil {
		return nil, err
	}

	desc.Checksum = namedDigest

	return desc, nil
}

func CalculateDigest(dbFilePath string) (string, error) {
	digest, err := file.HashFile(afero.NewOsFs(), dbFilePath, xxhash.New64())
	if err != nil {
		return "", fmt.Errorf("failed to calculate checksum for DB file: %w", err)
	}
	return fmt.Sprintf("xxh64:%s", digest), nil
}

func newPartialDescriptionFromDB(dbFilePath string) (*Description, error) {
	// access the DB to get the built time and schema version
	r, err := NewReader(Config{
		DBDirPath: filepath.Dir(dbFilePath),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read DB description: %w", err)
	}

	meta, err := r.GetDBMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to read DB metadata: %w", err)
	}

	return &Description{
		SchemaVersion: schemaver.New(meta.Model, meta.Revision, meta.Addition),
		Built:         Time{Time: *meta.BuildTimestamp},
	}, nil
}

func (m Description) String() string {
	return fmt.Sprintf("DB(version=%s built=%s checksum=%s)", m.SchemaVersion, m.Built, m.Checksum)
}

func WriteChecksums(writer io.Writer, m Description) error {
	if m.Checksum == "" {
		return fmt.Errorf("checksum is required")
	}

	if !strings.HasPrefix(m.Checksum, "xxh64:") {
		return fmt.Errorf("checksum missing algorithm prefix")
	}

	_, err := writer.Write([]byte(m.Checksum))
	return err
}
