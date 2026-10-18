package v6

import (
	"testing"

	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
)

var rollupOS = &db.OperatingSystem{Name: "chainguard", ReleaseID: "chainguard"}

func rollupRow(name, arch, cga string, ranges ...db.Range) db.AffectedPackageHandle {
	return db.AffectedPackageHandle{
		OperatingSystem: rollupOS,
		Package:         &db.Package{Name: name, Ecosystem: "apk"},
		BlobValue: &db.PackageBlob{
			CVEs:       []string{"CVE-2026-1", cga},
			Ranges:     ranges,
			Qualifiers: &db.PackageQualifiers{Architecture: &arch},
		},
	}
}

func fixedAt(v string) db.Range {
	return db.Range{
		Version: db.Version{Type: "apk", Constraint: "< " + v},
		Fix:     &db.Fix{Version: v, State: db.FixedStatus},
	}
}

func falsePositive() db.Range {
	return db.Range{Version: db.Version{Type: "apk", Constraint: "< 0"}}
}

func openWith(state db.FixStatus) db.Range {
	return db.Range{Fix: &db.Fix{State: state}}
}

func rolled(t *testing.T, rows ...db.AffectedPackageHandle) []db.AffectedPackageHandle {
	t.Helper()
	related := make([]any, len(rows))
	for i := range rows {
		related[i] = rows[i]
	}
	var out []db.AffectedPackageHandle
	for _, item := range rollupPackageRows(related) {
		out = append(out, item.(db.AffectedPackageHandle))
	}
	return out
}

// the #3798 shape: one copy of a component is a false positive, another is still open. One open
// row means no NAK reaches the matcher, so the open copy's owned findings survive on any grype.
func TestRollup_AnyOpenCopyWins(t *testing.T) {
	out := rolled(t,
		rollupRow("calico", "x86_64", "CGA-fp", falsePositive()),
		rollupRow("calico", "x86_64", "CGA-open", openWith(db.NotFixedStatus)),
		rollupRow("calico", "x86_64", "CGA-fixed", fixedAt("1.0.0-r1")),
	)
	require.Len(t, out, 1)
	require.Equal(t, []db.Range{openWith(db.NotFixedStatus)}, out[0].BlobValue.Ranges)
	require.Equal(t, []string{"CVE-2026-1", "CGA-open", "CGA-fixed", "CGA-fp"}, out[0].BlobValue.CVEs,
		"the winner's ids first, then the rest sorted, so arrival order does not change the blob")
}

func TestRollup_DisagreeingOpenCopiesLeaveTheStateUnknown(t *testing.T) {
	out := rolled(t,
		rollupRow("foo", "x86_64", "CGA-a", openWith(db.WontFixStatus)),
		rollupRow("foo", "x86_64", "CGA-b"), // detection: no range, unknown
	)
	require.Len(t, out, 1)
	require.Nil(t, out[0].BlobValue.Ranges, "wont-fix must not be inferred from one copy")

	out = rolled(t,
		rollupRow("foo", "x86_64", "CGA-a", openWith(db.WontFixStatus)),
		rollupRow("foo", "x86_64", "CGA-b", openWith(db.WontFixStatus)),
	)
	require.Equal(t, []db.Range{openWith(db.WontFixStatus)}, out[0].BlobValue.Ranges)
}

// the matcher already reports a package as vulnerable below the highest fix, so that is the
// row to keep; a false positive beside a fix adds nothing above it
func TestRollup_HighestFixWinsAndFalsePositivesDrop(t *testing.T) {
	out := rolled(t,
		rollupRow("foo", "x86_64", "CGA-low", fixedAt("1.0.0-r9")),
		rollupRow("foo", "x86_64", "CGA-fp", falsePositive()),
		rollupRow("foo", "x86_64", "CGA-high", fixedAt("1.0.0-r10")),
	)
	require.Len(t, out, 1)
	require.Equal(t, []db.Range{fixedAt("1.0.0-r10")}, out[0].BlobValue.Ranges, "apk ordering, not lexical")
}

func TestRollup_AllFalsePositivesStayOneNak(t *testing.T) {
	out := rolled(t,
		rollupRow("foo", "x86_64", "CGA-a", falsePositive()),
		rollupRow("foo", "x86_64", "CGA-b", falsePositive()),
	)
	require.Len(t, out, 1)
	require.Equal(t, []db.Range{falsePositive()}, out[0].BlobValue.Ranges)
}

// arch is a qualifier and so part of the key: an FP on one arch must not be rolled into the other
func TestRollup_GroupsByPackageAndQualifiers(t *testing.T) {
	out := rolled(t,
		rollupRow("foo", "x86_64", "CGA-a", falsePositive()),
		rollupRow("foo", "aarch64", "CGA-b", openWith(db.NotFixedStatus)),
		rollupRow("bar", "x86_64", "CGA-c", fixedAt("1.0.0-r1")),
	)
	require.Len(t, out, 3)
	require.Equal(t, "x86_64", *out[0].BlobValue.Qualifiers.Architecture)
	require.Equal(t, []db.Range{falsePositive()}, out[0].BlobValue.Ranges)
}

// rewriting any other shape could widen what an old client reports, so the group is left as is
func TestRollup_UnexpectedShapesPassThrough(t *testing.T) {
	lowerBound := db.Range{
		Version: db.Version{Type: "apk", Constraint: ">= 2.0.0-r0, < 2.1.0-r0"},
		Fix:     &db.Fix{Version: "2.1.0-r0", State: db.FixedStatus},
	}
	lastAffected := db.Range{Version: db.Version{Type: "apk", Constraint: "<= 1.0.0-r0"}}

	for name, odd := range map[string]db.Range{"lower bound": lowerBound, "last affected": lastAffected} {
		t.Run(name, func(t *testing.T) {
			out := rolled(t,
				rollupRow("foo", "x86_64", "CGA-a", odd),
				rollupRow("foo", "x86_64", "CGA-b", openWith(db.NotFixedStatus)),
			)
			require.Len(t, out, 2)
			require.Equal(t, []db.Range{odd}, out[0].BlobValue.Ranges)
		})
	}
}

func TestRollup_KeepsNonPackageItems(t *testing.T) {
	other := db.UnaffectedPackageHandle{Package: &db.Package{Name: "foo"}}
	out := rollupPackageRows([]any{other, rollupRow("foo", "x86_64", "CGA-a", falsePositive())})
	require.Len(t, out, 2)
	require.Equal(t, other, out[0])
}
