package v6

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/internal/log"
)

// This file folds entries that describe one vulnerability across many source records into a
// single VulnerabilityHandle. A transformer opts in per entry via RelatedEntries.MergeByName.
//
// The store's write-once dedup is not enough on its own. createRecordsWithCache keys on
// name + provider + blobID, so it only collapses already byte-identical blobs and resolves
// collisions by keeping the first writer. Measured on the chainguard feed that loses the dates
// of 10,677 of 11,784 handles (spreads reaching 321 days), and still re-splits 22 handles whose
// blobs differ. Merging unions the facts instead, so the result is arrival-order independent.

// Provider is in the key because two providers may legitimately publish the same CVE. Both
// parts are lowercased to match cacheKey, so the merger and the store agree on identity.
type mergeKey struct {
	provider string
	name     string
}

// The seen-sets live alongside the entry rather than being rebuilt per fold: chainguard folds
// ~1M records carrying ~20 references each, and rebuilding would make that quadratic.
type heldEntry struct {
	entry    transformers.RelatedEntries
	aliases  *strset.Set
	refs     *strset.Set
	severity *strset.Set
}

// nameMerger folds entries marked MergeByName into the first entry seen for their
// (provider, name). It owns none of the writer's concerns: the writer feeds it via hold and
// writes back whatever reconcile returns.
type nameMerger struct {
	held   map[mergeKey]*heldEntry
	order  []mergeKey
	folded int
}

func newNameMerger() *nameMerger {
	return &nameMerger{held: make(map[mergeKey]*heldEntry)}
}

// hold diverts an entry into the held set, returning true when the entry was held (and so must
// not be batched yet). Entries without MergeByName, or without a vulnerability handle to key
// on, are not held and stream through unchanged.
func (m *nameMerger) hold(entry transformers.RelatedEntries) bool {
	if !entry.MergeByName || entry.VulnerabilityHandle == nil {
		return false
	}

	key := mergeKey{
		provider: strings.ToLower(entry.VulnerabilityHandle.ProviderID),
		name:     strings.ToLower(entry.VulnerabilityHandle.Name),
	}

	existing, ok := m.held[key]
	if !ok {
		m.held[key] = newHeldEntry(entry)
		m.order = append(m.order, key)
		return true
	}

	existing.fold(entry)
	m.folded++
	return true
}

func newHeldEntry(entry transformers.RelatedEntries) *heldEntry {
	h := &heldEntry{
		entry:    entry,
		aliases:  strset.New(),
		refs:     strset.New(),
		severity: strset.New(),
	}
	if blob := entry.VulnerabilityHandle.BlobValue; blob != nil {
		h.aliases.Add(blob.Aliases...)
		for _, ref := range blob.References {
			h.refs.Add(referenceKey(ref))
		}
		for _, sev := range blob.Severities {
			h.severity.Add(severityKey(sev))
		}
	}
	return h
}

// Related rows are appended, never deduplicated: each carries its own originating CGA, and the
// duplicate findings they used to produce collapse at match time now that the name is shared.
func (h *heldEntry) fold(src transformers.RelatedEntries) {
	dst, s := h.entry.VulnerabilityHandle, src.VulnerabilityHandle

	if s.PublishedDate != nil && (dst.PublishedDate == nil || s.PublishedDate.Before(*dst.PublishedDate)) {
		dst.PublishedDate = s.PublishedDate
	}
	if s.ModifiedDate != nil && (dst.ModifiedDate == nil || s.ModifiedDate.After(*dst.ModifiedDate)) {
		dst.ModifiedDate = s.ModifiedDate
	}
	if s.WithdrawnDate != nil && (dst.WithdrawnDate == nil || s.WithdrawnDate.After(*dst.WithdrawnDate)) {
		dst.WithdrawnDate = s.WithdrawnDate
	}

	if dst.BlobValue != nil && s.BlobValue != nil {
		if dst.BlobValue.Description == "" {
			dst.BlobValue.Description = s.BlobValue.Description
		}
		for _, alias := range s.BlobValue.Aliases {
			if h.aliases.Has(alias) {
				continue
			}
			h.aliases.Add(alias)
			dst.BlobValue.Aliases = append(dst.BlobValue.Aliases, alias)
		}
		for _, ref := range s.BlobValue.References {
			key := referenceKey(ref)
			if h.refs.Has(key) {
				continue
			}
			h.refs.Add(key)
			dst.BlobValue.References = append(dst.BlobValue.References, ref)
		}
		for _, sev := range s.BlobValue.Severities {
			key := severityKey(sev)
			if h.severity.Has(key) {
				continue
			}
			h.severity.Add(key)
			dst.BlobValue.Severities = append(dst.BlobValue.Severities, sev)
		}
	}

	h.entry.Related = append(h.entry.Related, src.Related...)
}

// Neither db.Reference (Tags is a slice) nor db.Severity (Value is an interface) is safe to use
// as a map key directly, so both are rendered to strings.
func referenceKey(ref db.Reference) string {
	return ref.ID + "\x00" + ref.URL + "\x00" + strings.Join(ref.Tags, "\x00")
}

func severityKey(sev db.Severity) string {
	return fmt.Sprintf("%s\x00%v", sev.Scheme, sev.Value)
}

// reconcile returns the merged entries in first-appearance order and resets. The writer
// persists them through its normal batching path, so severity fill and fix-date checks run.
func (m *nameMerger) reconcile() []transformers.RelatedEntries {
	if len(m.order) == 0 {
		return nil
	}

	out := make([]transformers.RelatedEntries, 0, len(m.order))
	for _, key := range m.order {
		out = append(out, m.held[key].entry)
	}

	log.WithFields(
		"handles", len(m.order),
		"records", len(m.order)+m.folded,
	).Info("merged vulnerability records sharing a name")

	m.held = make(map[mergeKey]*heldEntry)
	m.order = nil
	m.folded = 0

	return out
}
