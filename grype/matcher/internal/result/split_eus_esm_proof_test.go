package result

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// This file is the specification for porting RHEL EUS (rpm/rhel_eus.go) and Ubuntu ESM
// (dpkg/ubuntu_esm.go) onto SplitVulnerable. Those two matchers are deliberately NOT changed yet;
// each case below drives the split with the record shapes from their fixtures and asserts the
// outcome their own matcher tests assert today, so the port can be committed to knowing the generic
// mechanism reaches the same answers.
//
// What the two are doing by hand maps onto the split like this:
//
//	two searches (base disclosures + base‖channel fixes)  -> one unconstrained FindAll, the
//	                                                         channel row ranked above base by the
//	                                                         confidence its search recorded
//	eusFixes/esmFixes -> disclosures.Remove(...)          -> the tier walk's "fix at or below this
//	                                                         version -> resolved, stop"
//	neededFixes (fix strictly above installed)            -> keeping only the windows this version
//	                                                         falls inside, whose fixes are above it
//	                                                         by construction
//	buildPatchedVulnerabilityRecord                       -> applicability and namespace from the
//	                                                         tier that answered; the fix comes from
//	                                                         the window that matched
//	finalizeMatchDetails                                  -> the split keeps each contributing
//	                                                         record's own details
//	finalizeFixState                                      -> match.fixStatePrecedence on merge
//	len(disclosures)==0 early return                      -> gone; see delta 2 below
//	isFixReachableForEUS                                  -> NOT expressible; see the open gap below
//
// Two deltas the port will carry, both of which look like fixes:
//
//  1. The disclosure searches currently apply OnlyVulnerableVersions, so a base disclosure whose
//     range misses the installed version is dropped at the DB layer before the channel can speak
//     about it. Fetching unconstrained removes that blind spot.
//  2. Losing the early return means the "installed at the base standard-pocket fix" case yields an
//     ownership ignore rather than nothing at all, which is what rpm standardMatches already does
//     for every non-channel package.
//
// The open gap: TestRedhatEUSMatches_HigherMinorOnlyFixStaysVulnerable is not expressible here, and
// deliberately has no case below. rhel9-eus holds a single rhel:8 rsync record whose only fix is
// 0:3.1.3-23.el8_10, with no +eus overlay for the CVE at all -- so for an 8.4+eus host the channel
// tier is *empty*, not lower-ranked, and the base window does cover the installed version and does
// name that fix. Nothing in any record distinguishes "this fix is yours" from "this fix ships on a
// minor you cannot reach"; only isFixReachableForEUS's string parse of `.elN_M` does. Resolving it
// means either teaching grype-db's OS transformer not to put an unreachable fix on an 8.4 row, or
// carrying that predicate into the split as a named remediation filter. That decision is still open
// and is the one piece of the port this file does not cover.

// esmVersion and eusVersion keep the two ecosystems' comparators straight.
func esmVersion(raw string) *version.Version { return version.New(raw, version.DebFormat) }
func eusVersion(raw string) *version.Version { return version.New(raw, version.RpmFormat) }

const (
	// Ubuntu ESM: the base pocket and the +esm channel for one LTS release.
	esmBaseNS    = "ubuntu:distro:ubuntu:16.04"
	esmChannelNS = "ubuntu:distro:ubuntu:16.04+esm"

	// RHEL EUS: the base minor's rows and the pinned +eus channel.
	eusBaseNS    = "redhat:distro:redhat:8.4"
	eusChannelNS = "redhat:distro:redhat:8.4+eus"
)

// streamRecord is one hydrated record: a single affected window, the fix it names, the namespace it
// came from and the tier of the row that produced it.
func streamRecord(namespace, constraint string, format version.Format, fixVersions ...string) vulnerability.Vulnerability {
	v := vulnerability.Vulnerability{
		Reference:   vulnerability.Reference{ID: "CVE-1", Namespace: namespace},
		PackageName: "pkg",
		Constraint:  version.MustGetConstraint(constraint, format),
	}
	if len(fixVersions) > 0 {
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: fixVersions}
	} else {
		// the "None"/won't-fix shape: the vendor acknowledges the package is affected and ships
		// nothing
		v.Fix = vulnerability.Fix{State: vulnerability.FixStateNotFixed}
	}
	return v
}

var proofPkg = pkg.Package{ID: "pkg-1", Name: "pkg"}

// each record's tier is derived from the role its namespace implies by the same function the
// matchers use, so these fixtures cannot drift from real ranking.
func proofSet(vulns ...vulnerability.Vulnerability) Set {
	var results []Result
	for _, v := range vulns {
		results = append(results, Result{
			ID:              "CVE-1",
			Package:         &proofPkg,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Details:         confidenceDetails(confidenceForNamespace(v.Namespace)),
		})
	}
	return Set{"CVE-1": results}
}

// reported flattens what the split would hand to ToMatches: the namespace the finding is reported
// under, and the fix it advertises.
type reported struct {
	namespace string
	state     vulnerability.FixState
	fixes     []string
}

func reportedFrom(t *testing.T, s Set) []reported {
	t.Helper()
	var out []reported
	for _, v := range s.Vulnerabilities() {
		out = append(out, reported{namespace: v.Namespace, state: v.Fix.State, fixes: v.Fix.Versions})
	}
	return out
}

// TestProof_UbuntuESM walks the scenarios TestUbuntuESM_VulnerableCases and
// TestUbuntuESM_FixedCases cover, in the same order.
func TestProof_UbuntuESM(t *testing.T) {
	const (
		basePocketFix = "1.11.0-2ubuntu1.1"
		esmFix        = "1.11.0-2ubuntu1.1+esm1"
	)

	t.Run("esm-only fix surfaced when installed below it", func(t *testing.T) {
		// the base pocket acknowledges the package and ships nothing; the esm channel ships the fix
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, "< "+esmFix, version.DebFormat, esmFix),
		)

		vulnerable, _ := s.SplitVulnerable(esmVersion("1.11.0-2ubuntu1"))

		// the channel is the more specific source and it says vulnerable, so its record is the one
		// reported -- carrying the esm fix, which is exactly what the matcher patches on today
		assert.Equal(t, []reported{{namespace: esmChannelNS, state: vulnerability.FixStateFixed, fixes: []string{esmFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("channel off leaves base wont-fix visible", func(t *testing.T) {
		// no esm channel on the distro means no channel row is searched at all
		s := proofSet(streamRecord(esmBaseNS, ">= 0", version.DebFormat))

		vulnerable, _ := s.SplitVulnerable(esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmBaseNS, state: vulnerability.FixStateNotFixed}},
			reportedFrom(t, vulnerable), "a Pro-only fix must never be treated as fixed for a non-Pro user")
	})

	t.Run("base standard-pocket fix still resolves with channel on", func(t *testing.T) {
		// the base pocket shipped a fix and esm has nothing to add: the channel tier is silent and
		// the question falls through to the base rows
		s := proofSet(streamRecord(esmBaseNS, "< "+basePocketFix, version.DebFormat, basePocketFix))

		vulnerable, _ := s.SplitVulnerable(esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmBaseNS, state: vulnerability.FixStateFixed, fixes: []string{basePocketFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("channel on with no esm fix stays vulnerable", func(t *testing.T) {
		// Pro subscription active but the package is still exposed
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, ">= 0", version.DebFormat),
		)

		vulnerable, _ := s.SplitVulnerable(esmVersion("1.11.0-2ubuntu1"))

		assert.Equal(t, []reported{{namespace: esmChannelNS, state: vulnerability.FixStateNotFixed}},
			reportedFrom(t, vulnerable))
	})

	t.Run("at esm fix is resolved", func(t *testing.T) {
		s := proofSet(
			streamRecord(esmBaseNS, ">= 0", version.DebFormat),
			streamRecord(esmChannelNS, "< "+esmFix, version.DebFormat, esmFix),
		)

		vulnerable, notVulnerable := s.SplitVulnerable(esmVersion(esmFix))

		// the channel's window does not cover this build and its fix is at this version, so the
		// channel answers "fixed" and stops -- the base won't-fix row never gets to override it
		require.Empty(t, vulnerable)
		require.NotEmpty(t, notVulnerable, "and carries out as the Distro Not Vulnerable ignore")
	})

	t.Run("at base standard-pocket fix is resolved", func(t *testing.T) {
		s := proofSet(streamRecord(esmBaseNS, "< "+basePocketFix, version.DebFormat, basePocketFix))

		vulnerable, notVulnerable := s.SplitVulnerable(esmVersion(basePocketFix))

		require.Empty(t, vulnerable)
		// delta 2: the matcher returns nothing at all here today, because its disclosure search is
		// version-constrained and it bails on an empty result. The split reports the record as
		// not-vulnerable instead, which is what the non-channel rpm path already does.
		require.NotEmpty(t, notVulnerable)
	})
}

// TestProof_RedhatEUS walks the EUS scenarios. See the open gap in this file's header for the one
// case that is deliberately absent.
func TestProof_RedhatEUS(t *testing.T) {
	const (
		eusFix  = "0:5.14.0-427.68.1.el9_4"
		mainFix = "0:5.14.0-503.11.1.el9_5"
	)

	t.Run("vulnerable on EUS", func(t *testing.T) {
		s := proofSet(
			streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix),
			streamRecord(eusChannelNS, "< "+eusFix, version.RpmFormat, eusFix),
		)

		vulnerable, _ := s.SplitVulnerable(eusVersion("0:5.14.0-300.el9_4"))

		// below both fixes: the pinned channel is the more specific source, so its fix is the one a
		// host on EUS is told to take
		assert.Equal(t, []reported{{namespace: eusChannelNS, state: vulnerability.FixStateFixed, fixes: []string{eusFix}}},
			reportedFrom(t, vulnerable))
	})

	t.Run("between the EUS fix and the mainline fix is resolved", func(t *testing.T) {
		s := proofSet(
			streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix),
			streamRecord(eusChannelNS, "< "+eusFix, version.RpmFormat, eusFix),
		)

		// 450 is past the EUS fix but below the mainline one
		vulnerable, notVulnerable := s.SplitVulnerable(eusVersion("0:5.14.0-450.el9_4"))

		// the EUS resolution wins because the host is on EUS: the channel answers "fixed" and stops
		// before the still-open base window is consulted
		require.Empty(t, vulnerable)
		require.NotEmpty(t, notVulnerable)
	})

	t.Run("a lower reachable channel fix resolves despite a higher base fix", func(t *testing.T) {
		// the shape of TestRedhatEUSMatches_LowerReachableFixResolvesDespiteHigherFix: the base row's
		// top fix is an unreachable higher-minor rebase, the channel carries the reachable backport,
		// and the host is at the backport. The unreachable base fix must not resurrect the finding.
		const (
			reachableChannelFix = "1:14.18.2-2.module+el8.4.0+13643+6c0ebf22"
			unreachableBaseFix  = "1:14.18.2-2.module+el8.5.0+13644+8d46dafd"
		)

		s := proofSet(
			streamRecord(eusBaseNS, "< "+unreachableBaseFix, version.RpmFormat, unreachableBaseFix),
			streamRecord(eusChannelNS, "< "+reachableChannelFix, version.RpmFormat, reachableChannelFix),
		)

		vulnerable, notVulnerable := s.SplitVulnerable(eusVersion(reachableChannelFix))

		require.Empty(t, vulnerable, "the channel tier answers 'fixed' and stops; the base tier is never asked")
		require.NotEmpty(t, notVulnerable)
	})

	t.Run("a channel with nothing to say falls through to the base rows", func(t *testing.T) {
		// no +eus overlay for this CVE: the channel tier is empty, so the base rows decide. This is
		// the shape the open gap sits in -- the split reaches the base row correctly, and only the
		// reachability of the fix it names is still unresolved.
		s := proofSet(streamRecord(eusBaseNS, "< "+mainFix, version.RpmFormat, mainFix))

		vulnerable, _ := s.SplitVulnerable(eusVersion("0:5.14.0-300.el9_4"))

		assert.Equal(t, []reported{{namespace: eusBaseNS, state: vulnerability.FixStateFixed, fixes: []string{mainFix}}},
			reportedFrom(t, vulnerable))
	})
}
