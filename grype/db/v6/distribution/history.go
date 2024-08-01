package distribution

import (
	"encoding/json"
	"fmt"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/spf13/afero"
	"os"
	"sort"
)

const (
	HistoryListingFileName = "history.json"
)

type HistoricalListingDocument struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion int `json:"schemaVersion"`

	// Status indicates the current status of this database schema version:
	//   active: the database is actively being maintained and distributed
	//   deprecated: the database is still being distributed but is approaching end of life. Upgrade grype to avoid future disruptions.
	//   eol: the database is no longer being distributed. Users must build their own databases or upgrade grype.
	Status string `json:"status"`

	// Notice is a message to be displayed to users of the database by the grype client
	Notice string `json:"notice,omitempty"`

	// Archives is a list of all previous databases that have been built and distributed within the last 90 days (not including the latest)
	Archives []Archive `json:"archives"`
}

func NewHistoricalListingDocument(entries ...Archive) HistoricalListingDocument {
	var finalEntries []Archive
	for _, entry := range entries {
		if entry.Description.SchemaVersion == nil || *entry.Description.SchemaVersion != db.SchemaVersion {
			continue
		}
		finalEntries = append(finalEntries, entry)
	}

	// sort from most recent to the least recent
	sort.SliceStable(finalEntries, func(i, j int) bool {
		return finalEntries[i].Description.Built.After(finalEntries[j].Description.Built.Time)
	})

	return HistoricalListingDocument{
		SchemaVersion: db.SchemaVersion,
		Archives:      finalEntries,
		Status:        LifecycleStatus,
	}
}

func NewHistoricalListingFromFile(fs afero.Fs, path string) (*HistoricalListingDocument, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open DB historical listing path: %w", err)
	}
	defer f.Close()

	var l HistoricalListingDocument
	err = json.NewDecoder(f).Decode(&l)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DB historical listing: %w", err)
	}

	// inflate entry data from parent
	for i, a := range l.Archives {
		if a.Description.SchemaVersion == nil {
			l.Archives[i].Description.SchemaVersion = &l.SchemaVersion
		}
	}

	return &l, nil
}

func (l HistoricalListingDocument) Write(toPath string) error {
	// collapse child data (save on space)
	for i := range l.Archives {
		l.Archives[i].Description.SchemaVersion = nil
	}

	contents, err := json.MarshalIndent(&l, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode historical listing file: %w", err)
	}

	err = os.WriteFile(toPath, contents, 0600)
	if err != nil {
		return fmt.Errorf("failed to write historical listing file: %w", err)
	}
	return nil
}
