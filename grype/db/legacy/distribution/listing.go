package distribution

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/afero"
)

const ListingFileName = "listing.json"

// Listing represents the json file which is served up and made available for applications to download and
// consume one or more vulnerability db flat files.
type Listing struct {
	Available map[int][]ListingEntry `json:"available"`
}

// NewListing creates a listing from one or more given ListingEntries.
func NewListing(entries ...ListingEntry) Listing {
	listing := Listing{
		Available: make(map[int][]ListingEntry),
	}
	for _, entry := range entries {
		if _, ok := listing.Available[entry.Version]; !ok {
			listing.Available[entry.Version] = make([]ListingEntry, 0)
		}
		listing.Available[entry.Version] = append(listing.Available[entry.Version], entry)
	}

	// sort each entry descending by date
	for idx := range listing.Available {
		listingEntries := listing.Available[idx]
		sort.SliceStable(listingEntries, func(i, j int) bool {
			return listingEntries[i].Built.After(listingEntries[j].Built)
		})
	}

	return listing
}

// NewListingFromFile loads a Listing from a given filepath.
func NewListingFromFile(fs afero.Fs, path string) (Listing, error) {
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

	// sort each entry descending by date
	for idx := range l.Available {
		listingEntries := l.Available[idx]
		sort.SliceStable(listingEntries, func(i, j int) bool {
			return listingEntries[i].Built.After(listingEntries[j].Built)
		})
	}

	return l, nil
}

// BestUpdate returns the ListingEntry from a Listing that meets the given version constraints.
func (l *Listing) BestUpdate(targetSchema int) *ListingEntry {
	if listingEntries, ok := l.Available[targetSchema]; ok {
		if len(listingEntries) > 0 {
			return &listingEntries[0]
		}
	}
	return nil
}

// Write the current listing to the given filepath.
func (l Listing) Write(toPath string) error {
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
