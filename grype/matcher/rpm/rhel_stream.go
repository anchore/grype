package rpm

import (
	"strings"

	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

// streamFix is a single per-stream called-out fix build extracted from an unaffected record:
// the fix EVR, its dist-tag minor (the N in .elM_N), and the advisory that shipped it.
type streamFix struct {
	evr      string
	minor    int
	hasMinor bool
	advisory vulnerability.Advisory
}

// applyStreamSelection implements Option A "matcher-side stream selection" for RHEL same-base
// multi-stream fixes.
//
// Red Hat sometimes fixes a package on several minor streams at the SAME upstream base, where only
// the .elN_M dist tag differs. Hydra flattens these under one "RHEL N" record, so vunnel collapses
// them to the single highest-EVR build. That makes grype false-positive a host that already carries
// its own stream's (lower-EVR) fix, because EVR is a single total order and cannot represent the
// per-minor branches.
//
// Option A keeps one disclosure record per CVE but carries every per-stream fix build + its advisory
// as unaffected ("= <evr>") records. Here we read the INSTALLED package's own dist-tag minor, select
// the per-stream fix whose dist-tag minor matches, and compare the installed version against it:
//
//   - installed >= its stream's fix  -> not vulnerable: move the disclosure to suppressed.
//   - installed <  its stream's fix  -> vulnerable: keep it, but rewrite Fix.Versions to THAT
//     stream's fix (not the collapsed highest build) so the reported remediation is reachable.
//
// Refine-or-fallback: if the package has no dist-tag minor, or no stream fix matches that minor,
// the disclosure is left untouched for the caller's coarse "< highest fix" handling. This never
// introduces a false negative - we only suppress when we positively matched the host's own stream.
//
// Returns (refinedDisclosures, suppressed). suppressed carries the per-vuln advisory of the matched
// stream fix so the caller can emit an accurate ignore.
func applyStreamSelection(searchPkg pkg.Package, disclosures, streamUnaffected result.Set) (refined, suppressed result.Set) {
	hostMinor, hostHasMinor := hostStreamMinor(searchPkg.Version)
	if !hostHasMinor {
		// no dist-tag minor on the installed package: cannot reason about streams, fall back.
		return disclosures, result.Set{}
	}

	pkgVersion := version.New(searchPkg.Version, version.RpmFormat)

	refined = result.Set{}
	suppressed = result.Set{}

	for id, results := range disclosures {
		fixes := streamFixesForID(id, streamUnaffected)
		matched, ok := selectStreamFixForMinor(fixes, hostMinor)
		if !ok {
			// no called-out stream fix matches the host's minor: leave for coarse handling.
			refined[id] = results
			continue
		}

		fixVersion := version.New(matched.evr, version.RpmFormat)
		cmp, err := pkgVersion.Compare(fixVersion)
		if err != nil {
			log.WithFields("package", searchPkg.Name, "vulnerability", id, "fix", matched.evr, "error", err).
				Trace("rpm: failed to compare installed version against stream fix; falling back to coarse handling")
			refined[id] = results
			continue
		}

		if cmp >= 0 {
			// installed >= the host's own stream fix: not vulnerable on this stream. Suppress.
			suppressed[id] = withAdvisory(results, matched.advisory)
			log.WithFields(
				"package", searchPkg.Name,
				"version", searchPkg.Version,
				"vulnerability", id,
				"streamFix", matched.evr,
				"advisory", matched.advisory.ID,
			).Trace("rpm: host is at/above its own stream's fix build; suppressing same-base false positive")
			continue
		}

		// installed < the host's own stream fix: still vulnerable, but the reachable remediation is
		// THIS stream's build, not the collapsed highest one. Rewrite the reported fix version.
		refined[id] = rewriteFixVersion(results, matched.evr)
	}

	return refined, suppressed
}

// hostStreamMinor extracts the dist-tag minor (the N in .elM_N) from an installed RPM version.
// Reuses the same release-parsing primitives as the EUS path. Returns ok=false when there is no
// dist-tag minor (e.g. a plain .elM build, or no dist tag at all).
func hostStreamMinor(rpmVersion string) (minor int, ok bool) {
	release := extractReleaseFromRPMVersion(rpmVersion)
	major, minor, found := extractRHELVersionFromRelease(release)
	if !found || major == 0 {
		return 0, false
	}
	// extractRHELVersionFromRelease returns minor=0 both for ".elM" (no minor) and ".elM_0".
	// We only want to key on streams that actually carry a minor, so require the "_" marker.
	if !strings.Contains(release, "_") {
		return 0, false
	}
	return minor, true
}

// streamFixesForID collects the per-stream fix builds (EVR + dist-tag minor + advisory) from the
// unaffected records that share an identity with the given disclosure ID.
func streamFixesForID(id string, streamUnaffected result.Set) []streamFix {
	var out []streamFix
	results, ok := streamUnaffected[id]
	if !ok {
		return out
	}
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			evr := evrFromConstraint(v)
			if evr == "" {
				continue
			}
			minor, hasMinor := hostStreamMinor(evr)
			sf := streamFix{evr: evr, minor: minor, hasMinor: hasMinor}
			if len(v.Advisories) > 0 {
				sf.advisory = v.Advisories[0]
			}
			out = append(out, sf)
		}
	}
	return out
}

// evrFromConstraint extracts the EVR from a "= <evr>" unaffected constraint. The exact-match
// unaffected handles emitted by the transformer encode the per-stream fix build as "= <evr>".
func evrFromConstraint(v vulnerability.Vulnerability) string {
	if v.Constraint == nil {
		return ""
	}
	raw := strings.TrimSpace(v.Constraint.Value())
	raw = strings.TrimPrefix(raw, "=")
	return strings.TrimSpace(raw)
}

// selectStreamFixForMinor returns the stream fix whose dist-tag minor equals the host's minor.
func selectStreamFixForMinor(fixes []streamFix, hostMinor int) (streamFix, bool) {
	for _, f := range fixes {
		if f.hasMinor && f.minor == hostMinor {
			return f, true
		}
	}
	return streamFix{}, false
}

// rewriteFixVersion returns a copy of the disclosure results with each vulnerability's reported fix
// version replaced by the host's own stream fix build, so grype reports a reachable remediation
// rather than the collapsed highest-stream build. Advisories are left intact (the disclosure already
// carries every contributing advisory via its AdvisorySummary).
func rewriteFixVersion(results []result.Result, evr string) []result.Result {
	out := make([]result.Result, 0, len(results))
	for _, r := range results {
		nr := r
		nr.Vulnerabilities = make([]vulnerability.Vulnerability, 0, len(r.Vulnerabilities))
		for _, v := range r.Vulnerabilities {
			nv := v
			if nv.Fix.State == vulnerability.FixStateFixed {
				nv.Fix.Versions = []string{evr}
			}
			nr.Vulnerabilities = append(nr.Vulnerabilities, nv)
		}
		out = append(out, nr)
	}
	return out
}

// withAdvisory returns a copy of the results with the matched stream advisory ensured present on each
// vulnerability, so a suppression ignore can reference the advisory whose fix the host already runs.
func withAdvisory(results []result.Result, adv vulnerability.Advisory) []result.Result {
	if adv.ID == "" && adv.Link == "" {
		return results
	}
	out := make([]result.Result, 0, len(results))
	for _, r := range results {
		nr := r
		nr.Vulnerabilities = make([]vulnerability.Vulnerability, 0, len(r.Vulnerabilities))
		for _, v := range r.Vulnerabilities {
			nv := v
			if !hasAdvisory(nv.Advisories, adv) {
				nv.Advisories = append(append([]vulnerability.Advisory(nil), nv.Advisories...), adv)
			}
			nr.Vulnerabilities = append(nr.Vulnerabilities, nv)
		}
		out = append(out, nr)
	}
	return out
}

func hasAdvisory(advisories []vulnerability.Advisory, adv vulnerability.Advisory) bool {
	for _, a := range advisories {
		if a.ID == adv.ID {
			return true
		}
	}
	return false
}
