package v6

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/grype/internal/schemaver"
)

var ErrDBDoesNotExist = errors.New("database does not exist")

type Description struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion schemaver.SchemaVer `json:"schemaVersion,omitempty"`

	// Built is the timestamp the database was built
	Built Time `json:"built"`
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

func DescriptionFromMetadata(m *DBMetadata) *Description {
	if m == nil {
		return nil
	}
	return &Description{
		SchemaVersion: schemaver.New(m.Model, m.Revision, m.Addition),
		Built:         Time{Time: *m.BuildTimestamp},
	}
}

func ReadDescription(dbFilePath string) (*Description, error) {
	// check if exists
	if _, err := os.Stat(dbFilePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrDBDoesNotExist
		}
		return nil, fmt.Errorf("failed to access database file: %w", err)
	}

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
	return fmt.Sprintf("DB(version=%s built=%s)", m.SchemaVersion, m.Built)
}
