package db

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hashicorp/go-version"
)

// TODO: move all of this to vulnscan-db

type ListingEntry struct {
	Built    time.Time // RFC 3339
	Version  *version.Version
	URL      *url.URL
	Checksum string
}

type ListingEntryJSON struct {
	Built    string `json:"built"`
	Version  string `json:"version"`
	URL      string `json:"url"`
	Checksum string `json:"checksum"`
}

func (l ListingEntryJSON) ToListingEntry() (ListingEntry, error) {
	build, err := time.Parse(time.RFC3339, l.Built)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot convert built time (%s): %+v", l.Built, err)
	}

	ver, err := version.NewVersion(l.Version)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot parse version (%s): %+v", l.Version, err)
	}

	u, err := url.Parse(l.URL)
	if err != nil {
		return ListingEntry{}, fmt.Errorf("cannot parse url (%s): %+v", l.URL, err)
	}

	return ListingEntry{
		Built:    build.UTC(),
		Version:  ver,
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

func (l ListingEntry) String() string {
	return fmt.Sprintf("Listing(url=%s)", l.URL)
}
