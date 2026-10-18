package v6

import (
	"encoding/json"
	"slices"
	"strings"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
)

// Chainguard files one record per (package x arch x bundled component), so once records are
// merged under one name a single apk can carry N rows for one vulnerability: e.g. one copy of a
// Go module a false positive ("< 0"), another copy still open. grype's apk matcher turns the
// false positive into an ownership ignore over every file the apk owns, which hides the open
// copy's own findings. Rolling the rows up to one per (OS, package, qualifiers) settles that in
// the data, so every grype that reads the DB, old or new, sees one verdict per package:
//
//   - any open copy -> open (with a fix state only if every open copy agrees on it);
//   - else any fixed copy -> the fixed row with the highest fix (false positives dropped);
//   - else (all false positive) -> one "< 0" row.
//
// "Highest fix" is what the matcher already computes from N fixed rows, since the lower fix is
// still vulnerable below the higher one. PackageBlob.CVEs becomes the union over the group, so
// every originating CGA stays on the row.
//
// A group holding any row that is not one of those three shapes (a lower bound, last_affected,
// a fix with no version) is passed through unrolled: rewriting it could widen what an old
// client reports, and leaving it is no worse than before rollup existed.

type rowKind int

const (
	rowUnrollable rowKind = iota
	rowFalsePositive
	rowFixed
	rowOpen
)

const nakConstraint = "< 0"

// classifyRow returns the row's shape and, for a fixed row, its highest fix version.
func classifyRow(b *db.PackageBlob) (rowKind, string) {
	if b == nil || len(b.Ranges) == 0 {
		return rowOpen, ""
	}
	open, nak := 0, 0
	var maxFix string
	for _, r := range b.Ranges {
		c := strings.TrimSpace(r.Version.Constraint)
		switch {
		case c == "":
			open++
		case c == nakConstraint:
			nak++
		case isUpperBoundOnly(c) && r.Fix != nil && r.Fix.Version != "" && c == "< "+r.Fix.Version:
			if maxFix == "" || apkLess(maxFix, r.Fix.Version) {
				maxFix = r.Fix.Version
			}
		default:
			return rowUnrollable, ""
		}
	}
	switch {
	case open == len(b.Ranges):
		return rowOpen, ""
	case open > 0:
		// an unbounded range beside bounded ones is not a shape the transformer emits
		return rowUnrollable, ""
	case maxFix != "":
		return rowFixed, maxFix
	case nak > 0:
		return rowFalsePositive, ""
	}
	return rowUnrollable, ""
}

func isUpperBoundOnly(c string) bool {
	return strings.HasPrefix(c, "< ") && !strings.ContainsAny(c[2:], "<>=,|")
}

func apkLess(a, b string) bool {
	c, err := version.New(a, version.ApkFormat).Compare(version.New(b, version.ApkFormat))
	if err != nil {
		return a < b
	}
	return c < 0
}

func rowGroupKey(h db.AffectedPackageHandle) string {
	var qualifiers *db.PackageQualifiers
	if h.BlobValue != nil {
		qualifiers = h.BlobValue.Qualifiers
	}
	k, _ := json.Marshal([]any{h.OperatingSystem, h.Package, qualifiers})
	return string(k)
}

// rollupPackageRows keeps items that are not AffectedPackageHandles as they are, and emits the
// rolled-up rows in the order each group was first seen.
func rollupPackageRows(related []any) []any {
	groups := map[string][]db.AffectedPackageHandle{}
	var order []string
	out := make([]any, 0, len(related))
	for _, item := range related {
		h, ok := item.(db.AffectedPackageHandle)
		if !ok {
			out = append(out, item)
			continue
		}
		k := rowGroupKey(h)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], h)
	}
	for _, k := range order {
		for _, h := range rollupGroup(groups[k]) {
			out = append(out, h)
		}
	}
	return out
}

func rollupGroup(rows []db.AffectedPackageHandle) []db.AffectedPackageHandle {
	if len(rows) == 1 {
		return rows
	}

	winner := -1
	winnerKind, winnerFix := rowUnrollable, ""
	var openStates []db.FixStatus
	for i := range rows {
		kind, fix := classifyRow(rows[i].BlobValue)
		switch kind {
		case rowUnrollable:
			log.WithFields("package", rows[i].Package, "rows", len(rows)).Trace("leaving package rows unrolled")
			return rows
		case rowOpen:
			openStates = append(openStates, openState(rows[i].BlobValue))
		}
		switch {
		case winner < 0,
			kind > winnerKind,
			kind == rowFixed && winnerKind == rowFixed && apkLess(winnerFix, fix):
			winner, winnerKind, winnerFix = i, kind, fix
		}
	}

	out := rows[winner]
	blob := db.PackageBlob{}
	if out.BlobValue != nil {
		blob = *out.BlobValue
	}
	blob.CVEs = unionCVEs(rows, winner)
	if winnerKind == rowOpen {
		// the transformer's encoding of an open row: no range when the state is unknown, else one
		// versionless range carrying the state
		blob.Ranges = nil
		if s := agreedState(openStates); s != "" && s != db.UnknownFixStatus {
			blob.Ranges = []db.Range{{Fix: &db.Fix{State: s}}}
		}
	}
	out.BlobValue = &blob
	return []db.AffectedPackageHandle{out}
}

// unionCVEs keeps the winner's ids first, in their order, then adds the rest sorted, so the
// blob does not depend on which record arrived first.
func unionCVEs(rows []db.AffectedPackageHandle, winner int) []string {
	var head, rest []string
	seen := map[string]struct{}{}
	add := func(dst *[]string, ids []string) {
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			*dst = append(*dst, id)
		}
	}
	if b := rows[winner].BlobValue; b != nil {
		add(&head, b.CVEs)
	}
	for i := range rows {
		if b := rows[i].BlobValue; b != nil && i != winner {
			add(&rest, b.CVEs)
		}
	}
	slices.Sort(rest)
	return append(head, rest...)
}

func openState(b *db.PackageBlob) db.FixStatus {
	if b == nil || len(b.Ranges) != 1 || b.Ranges[0].Fix == nil {
		return ""
	}
	return b.Ranges[0].Fix.State
}

func agreedState(states []db.FixStatus) db.FixStatus {
	if len(states) == 0 {
		return ""
	}
	for _, s := range states[1:] {
		if s != states[0] {
			return ""
		}
	}
	return states[0]
}
