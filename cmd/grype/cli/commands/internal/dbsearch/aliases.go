package dbsearch

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/log"
)

// maxAliasRows caps the alias rows read for each hop of relatedVulnerabilityNames
const maxAliasRows = 1000

// maxExpandedVulnerabilities caps the vulnerability specifiers a search expands to. All of them end up OR'd together in
// a single package or CPE query, which SQLite parses as one expression nested a level deeper per specifier, so this
// keeps that query under the SQLite expression depth limit (1000).
const maxExpandedVulnerabilities = 500

// expandAliases keeps the given specifiers and adds after them one specifier per related vulnerability name (see
// relatedVulnerabilityNames), keeping the other filters of the spec it came from. This runs once per search so the
// stores only ever see plain names. When there are more than maxExpandedVulnerabilities, related names are dropped
// before any given spec is, and evenly across the given specs (each one's direct links last to go).
func expandAliases(reader v6.VulnerabilityAliasStoreReader, specs v6.VulnerabilitySpecifiers) (v6.VulnerabilitySpecifiers, error) {
	var given, related v6.VulnerabilitySpecifiers
	seen := strset.New()
	add := func(to *v6.VulnerabilitySpecifiers, spec v6.VulnerabilitySpecifier) {
		// names are compared case-insensitively, like the stores do
		rest := spec
		rest.Name = ""
		key := strings.ToUpper(spec.Name) + "|" + rest.String()
		if !seen.Has(key) {
			seen.Add(key)
			*to = append(*to, spec)
		}
	}

	for _, spec := range specs {
		add(&given, spec)
	}

	// the related specs of each given spec, which are interleaved below so the cap doesn't drop one spec's relations
	// entirely just because it came last
	var relatedBySpec []v6.VulnerabilitySpecifiers
	for _, spec := range given {
		if spec.Name == "" {
			continue
		}
		names, err := relatedVulnerabilityNames(reader, spec.Name)
		if err != nil {
			return nil, err
		}
		var rs v6.VulnerabilitySpecifiers
		for _, name := range names {
			s := spec
			s.Name = name
			// the related names are already the full expansion, the store must not add its own alias hop on top
			s.IncludeAliases = false
			rs = append(rs, s)
		}
		relatedBySpec = append(relatedBySpec, rs)
	}
	for i := 0; ; i++ {
		more := false
		for _, rs := range relatedBySpec {
			if i < len(rs) {
				add(&related, rs[i])
				more = true
			}
		}
		if !more {
			break
		}
	}

	expanded := slices.Concat(given, related)
	if len(expanded) > maxExpandedVulnerabilities {
		log.WithFields("limit", maxExpandedVulnerabilities, "dropped", len(expanded)-maxExpandedVulnerabilities).Warn("too many related vulnerabilities, results only include some of them")
		expanded = expanded[:maxExpandedVulnerabilities]
	}
	return expanded, nil
}

// relatedVulnerabilityNames returns the vulnerability names linked to the given name through the alias table (not
// including the name itself), up to two hops in either direction (name -> alias and alias -> name). The direct links
// come first, then the names only reached through the second hop, each sorted. Two hops are
// needed since records often only reference each other through a shared ID, e.g. a GO record aliasing a GHSA which
// aliases a CVE. All comparisons are case-insensitive, like a direct search by name.
//
// The second hop is only taken through an intermediate ID linked to at most one CVE, on either side of the alias
// table: bundled distro advisories (e.g. ELSA, ALSA, ALAS) reference several CVEs without saying which packages are
// affected by which, so walking through them would pull in unrelated vulnerabilities. Note the guard only counts
// CVE-prefixed IDs, so an intermediate linked to several GHSAs and no CVE is still walked through.
func relatedVulnerabilityNames(reader v6.VulnerabilityAliasStoreReader, name string) ([]string, error) {
	key := strings.ToUpper

	// first hop: the name may be on either side of an alias row
	direct, err := reader.GetVulnerabilityAliases([]string{name}, maxAliasRows)
	if err != nil {
		if !errors.Is(err, v6.ErrLimitReached) {
			return nil, fmt.Errorf("unable to fetch vulnerability aliases for %q: %w", name, err)
		}
		// every row read is still a direct link, there are just more of them
		log.WithFields("vulnerability", name, "limit", maxAliasRows).Warn("too many aliases, results only include some of the related vulnerabilities")
	}

	intermediates := strset.New()
	for _, a := range direct {
		if key(a.Name) == key(name) {
			intermediates.Add(key(a.Alias))
		} else {
			intermediates.Add(key(a.Name))
		}
	}
	// an empty name would become a specifier without a name filter, matching every vulnerability its other filters allow
	intermediates.Remove(key(name), "")
	if intermediates.IsEmpty() {
		return nil, nil
	}

	directNames := intermediates.List()
	sort.Strings(directNames)

	// second hop: every alias row touching an intermediate, which also holds the rows needed to count its CVEs
	linked, err := reader.GetVulnerabilityAliases(intermediates.List(), maxAliasRows)
	if err != nil {
		if !errors.Is(err, v6.ErrLimitReached) {
			return nil, fmt.Errorf("unable to fetch linked vulnerability aliases for %q: %w", name, err)
		}
		// the CVE counts below can't be trusted on a partial read, a bundled advisory missing some of its rows would
		// look like it is linked to a single CVE and get walked through, so only the direct links are kept
		log.WithFields("vulnerability", name, "limit", maxAliasRows).Warn("too many linked aliases, results only include directly related vulnerabilities")
		return directNames, nil
	}

	// the distinct CVEs linked to each intermediate, from either side of the alias table
	cves := make(map[string]*strset.Set)
	addCVE := func(intermediate, other string) {
		if !intermediates.Has(intermediate) || !strings.HasPrefix(other, "CVE-") {
			return
		}
		if cves[intermediate] == nil {
			cves[intermediate] = strset.New()
		}
		cves[intermediate].Add(other)
	}
	for _, a := range linked {
		addCVE(key(a.Name), key(a.Alias))
		addCVE(key(a.Alias), key(a.Name))
	}
	walkable := func(id string) bool { return intermediates.Has(id) && (cves[id] == nil || cves[id].Size() <= 1) }

	secondHop := strset.New()
	for _, a := range linked {
		if walkable(key(a.Name)) {
			secondHop.Add(key(a.Alias))
		}
		if walkable(key(a.Alias)) {
			secondHop.Add(key(a.Name))
		}
	}
	secondHop.Remove(key(name), "")
	secondHop.Remove(directNames...)
	secondHopNames := secondHop.List()
	sort.Strings(secondHopNames)

	return slices.Concat(directNames, secondHopNames), nil
}
