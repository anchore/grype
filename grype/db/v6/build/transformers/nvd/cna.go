package nvd

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider/entry"
	"github.com/anchore/grype/internal/log"
)

// excludedCPEAssigners are CNAs whose cpeApplicability is not used for CPE rows. The Linux kernel CNA
// publishes ranges that all start at the commit that introduced a bug, and they are broader than the real set.
var excludedCPEAssigners = []string{"Linux"}

func cpeApplicabilityUsable(assigner string) bool {
	return !slices.Contains(excludedCPEAssigners, assigner)
}

// Index holds the CNA data of CVE 5 records, keyed by lowercased CVE ID, for the NVD transformer to look up.
type Index struct {
	records  map[string]unmarshal.CVE5Record
	consumed map[string]struct{}
	count    int
}

// NewIndex reads every record from the `cve5` provider's openers. It keeps a record when it has
// cpeApplicability or an affected entry with a packageURL or collectionURL, since nothing else is read later.
// A record that fails to decode is skipped with a warning and still counts as read.
func NewIndex(openers <-chan entry.Opener) (*Index, error) {
	idx := &Index{
		records:  make(map[string]unmarshal.CVE5Record),
		consumed: make(map[string]struct{}),
	}

	for opener := range openers {
		idx.count++

		f, err := opener.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open cache entry %q: %w", opener.String(), err)
		}
		envelope, err := unmarshal.Envelope(f)
		_ = f.Close()
		if err != nil {
			log.WithFields("record", opener.String(), "error", err).Warn("unable to decode CVE 5 record (skipping)")
			continue
		}

		records, err := unmarshal.CVE5Entries(bytes.NewReader(envelope.Item))
		if err != nil {
			log.WithFields("record", envelope.Identifier, "error", err).Warn("unable to decode CVE 5 record (skipping)")
			continue
		}

		for _, r := range records {
			idx.add(r)
		}
	}

	return idx, nil
}

func (i *Index) add(r unmarshal.CVE5Record) {
	key := strings.ToLower(r.CVEMetadata.CVEID)
	if key == "" {
		return
	}

	if _, exists := i.records[key]; exists {
		log.WithFields("cve", r.CVEMetadata.CVEID).Warn("duplicate CVE 5 record (keeping the later one)")
		delete(i.records, key)
	}

	if hasCNAData(r) {
		i.records[key] = r
	}
}

func hasCNAData(r unmarshal.CVE5Record) bool {
	if len(r.Containers.CNA.CPEApplicability) > 0 {
		return true
	}
	for _, a := range r.Containers.CNA.Affected {
		if a.PackageURL != "" || a.CollectionURL != "" {
			return true
		}
	}
	return false
}

// Count is the number of records read, whether or not they were kept.
func (i *Index) Count() int {
	return i.count
}

// Take returns the record for a CVE ID and marks it consumed, so Leftovers no longer returns it.
func (i *Index) Take(id string) (unmarshal.CVE5Record, bool) {
	key := strings.ToLower(id)
	r, ok := i.records[key]
	if ok {
		i.consumed[key] = struct{}{}
	}
	return r, ok
}

// Leftovers returns the published records that Take has not returned, sorted by CVE ID.
func (i *Index) Leftovers() []unmarshal.CVE5Record {
	var keys []string
	for key, r := range i.records {
		if _, taken := i.consumed[key]; taken || r.CVEMetadata.State != "PUBLISHED" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]unmarshal.CVE5Record, 0, len(keys))
	for _, key := range keys {
		out = append(out, i.records[key])
	}
	return out
}
