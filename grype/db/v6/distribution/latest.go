package distribution

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/schemaver"
)

const LatestFileName = "latest.json"

type LatestDocument struct {
	// Status indicates if the database is actively being maintained and distributed
	Status Status `json:"status"`

	// Archive is the most recent database that has been built and distributed, additionally annotated with provider-level information
	Archive `json:",inline"`
}

type Archive struct {
	// Description contains details about the database contained within the distribution archive
	db.Description `json:",inline"`

	// Path is the path to a DB archive relative to the listing file hosted location.
	// Note: this is NOT the absolute URL to download the database.
	Path string `json:"path"`

	// Checksum is the self describing digest of the database archive referenced in path
	Checksum string `json:"checksum"`
}

func NewLatestDocument(entries ...Archive) *LatestDocument {
	var validEntries []Archive
	for _, entry := range entries {
		if modelPart, ok := entry.SchemaVersion.ModelPart(); ok && modelPart == db.ModelVersion {
			validEntries = append(validEntries, entry)
		}
	}

	if len(validEntries) == 0 {
		return nil
	}

	// sort from most recent to the least recent
	sort.SliceStable(validEntries, func(i, j int) bool {
		return validEntries[i].Description.Built.After(entries[j].Description.Built.Time)
	})

	return &LatestDocument{
		Archive: validEntries[0],
		Status:  LifecycleStatus,
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

func NewArchive(path string, t time.Time, model, revision, addition int) (*Archive, error) {
	checksum, err := db.CalculateArchiveDigest(path)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate archive checksum: %w", err)
	}

	return &Archive{
		Description: db.Description{
			SchemaVersion: schemaver.New(model, revision, addition),
			Built:         db.Time{Time: t},
		},
		// this is not the path on disk, this is the path relative to the latest.json file when hosted
		Path:     filepath.Base(path),
		Checksum: checksum,
	}, nil
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

	contents, err := json.MarshalIndent(&l, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode listing file: %w", err)
	}

	_, err = writer.Write(contents)
	return err
}
