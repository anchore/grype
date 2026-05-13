package osv

import (
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

// Transform converts an OSV vulnerability record into grype DB entries by
// dispatching to a per-provider strategy keyed off the record's OSV id prefix.
//
// The strategy registry separates two orthogonal questions:
//   - which provider produced this record (the id prefix tells us)
//   - how that provider's record shape should be interpreted (the strategy decides)
//
// Each strategy owns its own decisions about affected-vs-advisory emission,
// alias augmentation, qualifier extraction, package/ecosystem mapping, and
// reference handling.
//
// Records that don't match any registered strategy are logged and skipped.
// Adding support for a new OSV-emitting provider is a deliberate act: write a
// new transform_<provider>.go that decides what the records mean, then
// register it in `strategies` below. Falling back to "generic" emission would
// hide ignorance about a new provider's record shape and risk silently
// producing wrong DB entries.
func Transform(vulnerability unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error) {
	for _, s := range strategies {
		if s.Matches(vulnerability.ID) {
			return s.Transform(vulnerability, state)
		}
	}
	log.WithFields("id", vulnerability.ID, "provider", state.Provider).
		Warn("no OSV strategy matched record; skipping (add a transform_<provider>.go to handle this provider)")
	return nil, nil
}

// Strategy is the per-provider OSV record interpreter. Matches checks whether
// this strategy claims a given record ID; Transform produces the DB entries.
type Strategy interface {
	Matches(id string) bool
	Transform(vuln unmarshal.OSVVulnerability, state provider.State) ([]data.Entry, error)
}

// strategies is the dispatch order: the first strategy whose Matches returns
// true handles the record. Add new providers by appending here.
var strategies = []Strategy{
	almaStrategy{},
	bitnamiStrategy{},
}
