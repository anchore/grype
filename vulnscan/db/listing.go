package db

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/vulnscan/internal/file"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/hashicorp/go-version"
	"github.com/spf13/afero"
)

// TODO: move all of this to vulnscan-db

type Listing struct {
	Latest    ListingEntry   `json:"latest"`
	Available []ListingEntry `json:"available"`
}

func newListingFromPath(fs afero.Fs, path string) (Listing, error) {
	f, err := fs.Open(path)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to open DB listing path: %w", err)
	}
	defer f.Close()

	var l Listing
	err = json.NewDecoder(f).Decode(&l)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to parse DB listing: %w", err)
	}
	return l, nil
}

func newListingFromURL(fs afero.Fs, getter file.Getter, listingURL string) (Listing, error) {
	tempFile, err := afero.TempFile(fs, "", "vulnscan-listing")
	if err != nil {
		return Listing{}, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer func() {
		err := fs.RemoveAll(tempFile.Name())
		if err != nil {
			log.Errorf("failed to remove file (%s): %w", tempFile.Name(), err)
		}
	}()

	// download the listing file
	err = getter.GetFile(tempFile.Name(), listingURL)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := newListingFromPath(fs, tempFile.Name())
	if err != nil {
		return Listing{}, err
	}
	return listing, nil
}

func (l *Listing) bestUpdate(constraint version.Constraints) *ListingEntry {
	// extract the latest available db
	candidates := []ListingEntry{l.Latest}
	candidates = append(candidates, l.Available...)

	// TODO: sort candidates by version and built date

	for _, candidate := range candidates {
		log.Debugf("found update: %s", candidate)
	}

	var updateEntry *ListingEntry
	for _, candidate := range candidates {
		if constraint.Check(candidate.Version) {
			copy := candidate
			updateEntry = &copy
			break
		}
	}

	return updateEntry
}
