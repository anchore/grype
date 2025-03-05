package distribution

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"time"

	"github.com/spf13/afero"

	"github.com/anchore/grype/internal/file"
)

// ListingEntry represents basic metadata about a database archive such as what is in the archive (built/version)
// as well as how to obtain and verify the archive (URL/checksum).
type ListingEntry struct {
	Built    time.Time // RFC 3339
	Version  int
	URL      *url.URL
	Checksum string
}

// ListingEntryJSON is a helper struct for converting a ListingEntry into JSON (or parsing from JSON)
type ListingEntryJSON struct {
	Built    string `json:"built"`
	Version  int    `json:"version"`
	URL      string `json:"url"`
	Checksum string `json:"checksum"`
}

// NewListingEntryFromArchive creates a new ListingEntry based on the metadata from a database flat file.
func NewListingEntryFromArchive(fs afero.Fs, metadata Metadata, dbArchivePath string, baseURL *url.URL) (ListingEntry, error) {
	checksum, err := file.HashFile(fs, dbArchivePath, sha256.New())
	if err != nil {
		return ListingEntry{}, fmt.Errorf("unable to find db archive checksum: %w", err)
	}

	dbArchiveName := filepath.Base(dbArchivePath)
	fileURL, _ := url.Parse(baseURL.String())
	fileURL.Path = path.Join(fileURL.Path, dbArchiveName)

	return ListingEntry{
		Built:    metadata.Built,
		Version:  metadata.Version,
		URL:      fileURL,
		Checksum: "sha256:" + checksum,
	}, nil
}

// ToListingEntry converts a ListingEntryJSON to a ListingEntry.
func (l ListingEntryJSON) ToListingEntry() (ListingEntry, error) {
	build, err := time.Parse(time.RFC3339, l.Built)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot convert built time (%s): %+v", l.Built, err)
	}

	u, err := url.Parse(l.URL)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot parse url (%s): %+v", l.URL, err)
	}

	return ListingEntry{
		Built:    build.UTC(),
		Version:  l.Version,
		URL:      u,
		Checksum: l.Checksum,
	}, nil
}

func (l *ListingEntry) UnmarshalJSON(data []byte) error {
	var lej ListingEntryJSON
	if err := json.Unmarshal(data, &lej); err != nil {
		return err
	}
	le, err := lej.ToListingEntry()
	if err != nil {
		return err
	}
	*l = le
	return nil
}

func (l *ListingEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ListingEntryJSON{
		Built:    l.Built.Format(time.RFC3339),
		Version:  l.Version,
		Checksum: l.Checksum,
		URL:      l.URL.String(),
	})
}

func (l ListingEntry) String() string {
	return fmt.Sprintf("Listing(url=%s)", l.URL)
}
