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
	LatestListingFileName = "listing.json"
	LifecycleStatus       = "active" // valid values: active, deprecated, eol
)

type ListingDocument struct {
	// SchemaVersion is the version of the DB schema
	SchemaVersion int `json:"schemaVersion"`

	// Status indicates the current status of this database schema version:
	//   active: the database is actively being maintained and distributed
	//   deprecated: the database is still being distributed but is approaching end of life. Upgrade grype to avoid future disruptions.
	//   eol: the database is no longer being distributed. Users must build their own databases or upgrade grype.
	Status string `json:"status"`

	// Notice is a message to be displayed to users of the database by the grype client
	Notice string `json:"notice,omitempty"`

	// Archive is the most recent database that has been built and distributed, additionally annotated with provider-level information
	Archive Archive `json:"archive"`
}

type Archive struct {
	// Description contains details about the database contained within the distribution archive
	Description DatabaseDescription `json:"database"`

	// Path is the path to a DB archive relative to the listing file hosted location.
	// Note: this is NOT the absolute URL to download the database.
	Path string `json:"path"`

	// Checksum is the self describing digest of the database archive referenced in path
	Checksum string `json:"checksum"`
}

type ProviderInfo struct {
	// Name of the vunnel provider
	Name string `json:"name"`

	// Compiled is the timestamp the data was pulled from upstream data sources
	Compiled Time `json:"compiled"` // RFC 3339

	// TODO: vunnel and/or provider version
}

func NewListingDocument(entries ...Archive) *ListingDocument {
	if len(entries) == 0 {
		return nil
	}

	// sort from most recent to the least recent
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Description.Built.After(entries[j].Description.Built.Time)
	})

	return &ListingDocument{
		SchemaVersion: db.SchemaVersion,
		Archive:       entries[0],
		Status:        LifecycleStatus,
	}
}

func NewListingFromFile(fs afero.Fs, path string) (*ListingDocument, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open DB listing path: %w", err)
	}
	defer f.Close()

	var l ListingDocument
	err = json.NewDecoder(f).Decode(&l)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DB listing: %w", err)
	}

	// inflate entry data from parent
	if l.Archive.Description.SchemaVersion != nil {
		l.Archive.Description.SchemaVersion = &l.SchemaVersion
	}

	return &l, nil
}

func (l ListingDocument) Write(toPath string) error {
	// collapse child data (save on space)
	l.Archive.Description.SchemaVersion = nil

	contents, err := json.MarshalIndent(&l, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode listing file: %w", err)
	}

	err = os.WriteFile(toPath, contents, 0600)
	if err != nil {
		return fmt.Errorf("failed to write listing file: %w", err)
	}
	return nil
}
