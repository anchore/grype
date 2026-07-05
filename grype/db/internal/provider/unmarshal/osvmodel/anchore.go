package osvmodel

import "encoding/json"

// AnchoreAffected is the grype-owned overlay stamped onto an OSV
// affected[].database_specific by vunnel before grype-db consumes the record.
// Anything outside this namespace is vendor-defined and read by per-provider
// extension types in the transformer package.
type AnchoreAffected struct {
	// Status carries a normalized disposition that the upstream OSV record
	// does not express directly. Currently observed: "wont-fix" (the provider
	// explicitly will not patch this on this release).
	Status string `json:"status,omitempty"`
}

// AnchoreRange is the grype-owned overlay on an
// affected[].ranges[].database_specific. Today it only carries
// fix-availability metadata sourced from vunnel's fix-date tracking.
type AnchoreRange struct {
	Fixes []AnchoreFix `json:"fixes,omitempty"`
}

// AnchoreFix is one entry in AnchoreRange.Fixes. Date is a string rather than
// time.Time so callers control the parse (some emit RFC3339, some date-only).
type AnchoreFix struct {
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Date    string `json:"date"`
}

// AffectedExtension returns the "anchore" key from an Affected's
// database_specific map as a typed view. Missing key or decode failure yields
// the zero value — both are treated as "no overlay" by the transformers.
func AffectedExtension(databaseSpecific map[string]any) AnchoreAffected {
	var ext AnchoreAffected
	DecodeNamespace(databaseSpecific, "anchore", &ext)
	return ext
}

// RangeExtension returns the "anchore" key from a Range's database_specific
// map as a typed view. Missing key or decode failure yields the zero value.
func RangeExtension(databaseSpecific map[string]any) AnchoreRange {
	var ext AnchoreRange
	DecodeNamespace(databaseSpecific, "anchore", &ext)
	return ext
}

// DecodeNamespace pulls a single key out of an extension-point map and
// decodes its JSON shape into the target. Errors are swallowed: the caller
// either gets a populated target or the zero value, with no way to tell the
// difference. That matches the transformers' "absence == no overlay" posture
// and avoids re-flagging vunnel write-side bugs at read time.
//
// Use this when the vendor namespaces their extension under a single key
// (the dominant shape, e.g. "anchore" or future "vendorname").
func DecodeNamespace(m map[string]any, key string, into any) {
	raw, ok := m[key]
	if !ok {
		return
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, into)
}

// DecodeAll decodes an entire extension-point map into the target. Use this
// when a vendor sticks fields at the top level of database_specific or
// ecosystem_specific (e.g. alma's affected[].ecosystem_specific.rpm_modularity)
// rather than under a namespacing key.
func DecodeAll(m map[string]any, into any) {
	if len(m) == 0 {
		return
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, into)
}
