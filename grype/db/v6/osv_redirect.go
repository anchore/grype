package v6

import "strings"

// OSV redirect: Chainguard publishes its advisories as a secdb feed and as an OSV feed. Released grype
// mishandles the OSV rows on subpackages (it applies an origin's per-binary rows to every subpackage),
// so the DB keeps today's secdb rows under the `chainguard` and `wolfi` OSs, unchanged, and puts the
// OSV rows under OSs of their own (`chainguard-osv`, `wolfi-osv`) that no released client looks up:
// released clients find OS rows by `name = ? OR release_id = ?` on the distro name, so a different
// name and release ID hides them.
//
// A client that carries the fix for those rows (the apk origin copy marked arch "src") follows a
// search rule from the DB that replaces its apk searches of `chainguard` and `wolfi` with searches of
// the OSV OSs. The rule is never built in (it is not in KnownSearchRules): a DB without OSV rows has no
// rule and is searched as before. The DB writer emits it only for an OSV OS it wrote rows to (see
// OSVRedirectSearchRules).
const (
	chainguardDistro = "chainguard"
	wolfiDistro      = "wolfi"

	// osvRedirectSuffix names the OS holding a distro's OSV rows, e.g. "chainguard-osv"
	osvRedirectSuffix = "-osv"

	// OSVRedirectClientDBSchemas gates the redirect to clients with the subpackage fix. It is the schema
	// addition that fix shipped in, and must never move with later additions: a client that reads
	// search rules but lacks the fix (schema 6.1.11, which introduced search_rules) must not follow it.
	OSVRedirectClientDBSchemas = ">= 6.1.12"
)

// osvRedirectSources are the distros whose apk OSV rows live under their own OS.
var osvRedirectSources = []string{chainguardDistro, wolfiDistro}

// OSVRedirectTarget is the name (and release ID) of the OS holding the OSV rows of distro, e.g.
// "chainguard-osv" for "chainguard"; false for a distro that is not redirected.
func OSVRedirectTarget(distro string) (string, bool) {
	lower := strings.ToLower(distro)
	for _, src := range osvRedirectSources {
		if lower == src {
			return src + osvRedirectSuffix, true
		}
	}
	return "", false
}

// osvRedirectSource is the distro whose OSV rows the OS named target holds, e.g. "chainguard" for
// "chainguard-osv"; false for any other OS.
func osvRedirectSource(target string) (string, bool) {
	lower := strings.ToLower(target)
	for _, src := range osvRedirectSources {
		if lower == src+osvRedirectSuffix {
			return src, true
		}
	}
	return "", false
}

// OSVRedirectSearchRules are the search rules that send a fixed client's apk searches of a distro to
// the OS holding its OSV rows, keyed by that OS's name. They are NOT built in: the DB writer emits the
// rule for an OS only when it wrote rows to it, so a client on a DB without OSV rows searches the
// distro's own rows as before.
//
// The searched version is dropped: both distros are rolling, and the OSV OS rows are version-less
// (label "rolling"). The search names the OS exactly, so no OS alias applies to it.
func OSVRedirectSearchRules() map[string]SearchRule {
	out := make(map[string]SearchRule, len(osvRedirectSources))
	for _, src := range osvRedirectSources {
		target, _ := OSVRedirectTarget(src)
		out[target] = SearchRule{
			Action:                    SearchRuleReplace,
			MatchDistroName:           src,
			MatchEcosystem:            apkEcosystem,
			ReplacementDistroName:     ptr(target),
			ReplacementDistroVersion:  ptr(""),
			ApplicableClientDBSchemas: OSVRedirectClientDBSchemas,
		}
	}
	return out
}
