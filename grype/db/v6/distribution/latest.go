package distribution

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/anchore/grype/grype/db/internal/schemaver"
	db "github.com/anchore/grype/grype/db/v6"
)

const LatestFileName = "latest.json"

type LatestDocument struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion schemaver.SchemaVer `json:"schemaVersion"`

	// Status indicates if the database is actively being maintained and distributed
	Status Status `json:"status"`

	// Archive is the most recent database that has been built and distributed, additionally annotated with provider-level information
	Archive Archive `json:"archive"`
}

type Archive struct {
	// Description contains details about the database contained within the distribution archive
	Description db.Description `json:"database"`

	// Path is the path to a DB archive relative to the listing file hosted location.
	// Note: this is NOT the absolute URL to download the database.
	Path string `json:"path"`

	// Checksum is the self describing digest of the database archive referenced in path
	Checksum string `json:"checksum"`
}

func NewLatestDocument(entries ...Archive) *LatestDocument {
	if len(entries) == 0 {
		return nil
	}

	// sort from most recent to the least recent
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Description.Built.After(entries[j].Description.Built.Time)
	})

	return &LatestDocument{
		SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
		Archive:       entries[0],
		Status:        LifecycleStatus,
	}
}

func NewLatestFromReader(reader io.Reader) (*LatestDocument, error) {
	var l LatestDocument

	if err := json.NewDecoder(reader).Decode(&l); err != nil {
		return nil, fmt.Errorf("unable to parse DB latest.json: %w", err)
	}

	// inflate entry data from parent
	if l.Archive.Description.SchemaVersion != "" {
		l.Archive.Description.SchemaVersion = l.SchemaVersion
	}

	return &l, nil
}

func (l LatestDocument) Write(writer io.Writer) error {
	if l.SchemaVersion == "" {
		return fmt.Errorf("missing schema version")
	}

	if l.Status == "" {
		l.Status = LifecycleStatus
	}

	if l.Archive.Path == "" {
		return fmt.Errorf("missing archive path")
	}

	if l.Archive.Checksum == "" {
		return fmt.Errorf("missing archive checksum")
	}

	if l.Archive.Description.Built.Time.IsZero() {
		return fmt.Errorf("missing built time")
	}

	if l.Archive.Description.Checksum == "" {
		return fmt.Errorf("missing database checksum")
	}

	// we don't need to store duplicate information from the archive section in the doc
	l.Archive.Description.SchemaVersion = ""

	contents, err := json.MarshalIndent(&l, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode listing file: %w", err)
	}

	_, err = writer.Write(contents)
	return err
}
