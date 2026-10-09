package nvd

import (
	"bytes"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider/entry"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers/internal"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
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

// cnaRegistryHosts maps a purl type to the registry hosts that identify it in a collectionURL. An entry with a
// path (wordpress.org/plugins) also needs the URL path to start with it. This is the table in the
// cna-reconciliation spec's supported-ecosystems requirement.
var cnaRegistryHosts = map[string][]string{
	packageurl.TypeMaven:    {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com", "search.maven.org"},
	packageurl.TypePyPi:     {"pypi.org", "pypi.python.org"},
	packageurl.TypeNPM:      {"registry.npmjs.org", "www.npmjs.com", "npmjs.com"},
	packageurl.TypeGolang:   {"pkg.go.dev", "proxy.golang.org"},
	packageurl.TypeCargo:    {"crates.io"},
	packageurl.TypeGem:      {"rubygems.org"},
	packageurl.TypeComposer: {"packagist.org"},
	packageurl.TypeNuget:    {"www.nuget.org", "nuget.org"},
	packageurl.TypeHex:      {"hex.pm", "repo.hex.pm"},
	packageurl.TypePub:      nil,
	packageurl.TypeSwift:    nil,
	"wordpress-plugin":      {"wordpress.org/plugins"},
}

// cnaPackageHandles returns one affected package handle for each affected[] entry that names a package in a
// supported ecosystem and has at least one range that is no broader than the entry states. An entry that cannot be
// used is skipped with a debug log, never an error.
func cnaPackageHandles(r unmarshal.CVE5Record) []db.AffectedPackageHandle {
	cve := r.CVEMetadata.CVEID

	var handles []db.AffectedPackageHandle
	for _, a := range r.Containers.CNA.Affected {
		purl, ok := cnaPackageIdentity(a)
		if !ok {
			continue
		}

		if a.DefaultStatus == "affected" {
			// the affected set is everything outside the unaffected items, which ranges from affected items cannot express
			log.WithFields("cve", cve, "package", purl.Name).Debug("skipping CNA entry: defaultStatus is affected")
			continue
		}

		ranges := cnaRanges(cve, purl.Type, a.Versions)
		if len(ranges) == 0 {
			log.WithFields("cve", cve, "package", purl.Name).Debug("skipping CNA entry: no usable range")
			continue
		}

		pkgType := syftPkg.TypeByName(purl.Type)
		handles = append(handles, db.AffectedPackageHandle{
			Package: &db.Package{
				Name:      name.Normalize(internal.PackageNameFromPURL(purl), pkgType),
				Ecosystem: string(pkgType),
			},
			BlobValue: &db.PackageBlob{
				CVEs:   []string{cve},
				Ranges: ranges,
			},
		})
	}
	return handles
}

// cnaPackageIdentity finds the package an affected[] entry names. A purl whose type is supported wins over the
// collectionURL and packageName. Otherwise a packageName on a supported registry host is used.
func cnaPackageIdentity(a unmarshal.CVE5Affected) (*packageurl.PackageURL, bool) {
	if a.PackageURL != "" {
		purl, err := packageurl.FromString(a.PackageURL)
		// a swift purl without a version is rejected by the parser, but its type and name are still set
		if err != nil && purl.Type != packageurl.TypeSwift {
			purl = packageurl.PackageURL{}
		}
		if _, supported := cnaRegistryHosts[purl.Type]; supported && purl.Name != "" {
			// a maven purl without a group names no package a GitHub advisory could also name
			if purl.Type == packageurl.TypeMaven && purl.Namespace == "" {
				return nil, false
			}
			return &purl, true
		}
	}

	if a.PackageName == "" {
		return nil, false
	}

	purlType, ok := cnaTypeFromCollectionURL(a.CollectionURL)
	if !ok {
		return nil, false
	}

	purl := packageurl.PackageURL{Type: purlType, Name: a.PackageName}
	if purlType == packageurl.TypeMaven {
		group, artifact, found := strings.Cut(a.PackageName, ":")
		if !found || group == "" || artifact == "" || strings.Contains(artifact, ":") {
			return nil, false
		}
		purl.Namespace, purl.Name = group, artifact
	}
	return &purl, true
}

// cnaTypeFromCollectionURL matches a collectionURL to a purl type, ignoring scheme, host case and any path after
// the host except where the table names one.
func cnaTypeFromCollectionURL(collectionURL string) (string, bool) {
	if collectionURL == "" {
		return "", false
	}
	if !strings.Contains(collectionURL, "://") {
		collectionURL = "https://" + collectionURL
	}
	u, err := url.Parse(collectionURL)
	if err != nil {
		return "", false
	}

	host := strings.ToLower(u.Hostname())
	for purlType, hosts := range cnaRegistryHosts {
		for _, h := range hosts {
			h, pathPrefix, _ := strings.Cut(h, "/")
			if host == h && (pathPrefix == "" || strings.HasPrefix(u.Path, "/"+pathPrefix)) {
				return purlType, true
			}
		}
	}
	return "", false
}

// cnaRanges maps each version item to at most one range. See the cna-reconciliation spec's
// ranges-no-broader-than-stated requirement: an item that cannot be expressed without admitting versions the
// CNA did not mark affected is dropped, and the other items are kept.
func cnaRanges(cve, purlType string, items []unmarshal.CVE5Version) []db.Range {
	var ranges []db.Range
	for _, item := range items {
		r, reason := cnaRange(purlType, item)
		if r == nil {
			if reason != "" {
				log.WithFields("cve", cve, "version", item.Version, "reason", reason).Debug("skipping CNA version item")
			}
			continue
		}
		ranges = append(ranges, *r)
	}
	return ranges
}

func cnaRange(purlType string, item unmarshal.CVE5Version) (*db.Range, string) {
	if item.Status != "affected" {
		return nil, ""
	}

	lower, upper := item.Version, item.LessThan
	inclusive := false
	switch {
	case item.LessThan != "" && item.LessThanOrEqual != "":
		return nil, "both lessThan and lessThanOrEqual are set"
	case item.LessThanOrEqual != "":
		upper, inclusive = item.LessThanOrEqual, true
	}

	if lower == "" || cnaUnusableVersion(lower, false) || cnaUnusableVersion(upper, true) {
		return nil, "version is a placeholder or free text"
	}

	placeholder := lower == "0" || strings.EqualFold(lower, "n/a")
	var constraint string
	switch {
	case placeholder && (upper == "" || upper == "*"):
		return nil, "no bound on either side"
	case placeholder && inclusive:
		constraint = "<= " + upper
	case placeholder:
		constraint = "< " + upper
	case upper == "*":
		constraint = ">= " + lower
	case upper == "":
		constraint = "= " + lower
	case inclusive:
		constraint = fmt.Sprintf(">= %s, <= %s", lower, upper)
	default:
		constraint = fmt.Sprintf(">= %s, < %s", lower, upper)
	}

	format := version.ParseFormat(purlType)

	// a change inside the range makes the range cover versions the item does not mark affected
	bound := upper
	if bound == "" {
		bound = lower
	}
	if bound == "*" && len(item.Changes) > 0 {
		return nil, "changes with no upper bound"
	}
	for _, c := range item.Changes {
		if bound == "*" {
			break
		}
		below, err := version.New(c.At, format).Compare(version.New(bound, format))
		if err != nil || below < 0 {
			return nil, "change inside the range"
		}
	}

	v := db.Version{Type: purlType, Constraint: constraint}
	if err := internal.ValidateAffectedVersion(v); err != nil {
		return nil, fmt.Sprintf("constraint does not validate: %v", err)
	}

	r := &db.Range{Version: v}
	if upper != "" && upper != "*" && !inclusive {
		r.Fix = &db.Fix{Version: upper, State: db.FixedStatus}
	}
	return r, ""
}

// cnaUnusableVersion is true for a version holding constraint syntax, whitespace or an unspecified marker. A "*"
// is allowed only as a whole upper bound.
func cnaUnusableVersion(v string, upperBound bool) bool {
	if v == "*" {
		return !upperBound
	}
	return strings.IndexFunc(v, unicode.IsSpace) >= 0 ||
		strings.ContainsAny(v, "<>=,*") ||
		strings.EqualFold(v, "unspecified") ||
		strings.EqualFold(v, "unknown")
}
