package nvd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider/entry"
)

type bytesOpener struct {
	name     string
	contents []byte
	err      error
}

func (o bytesOpener) Open() (io.ReadCloser, error) {
	if o.err != nil {
		return nil, o.err
	}
	return io.NopCloser(bytes.NewReader(o.contents)), nil
}

func (o bytesOpener) String() string { return o.name }

// cve5Envelope wraps item the way vunnel writes it to a results store.
func cve5Envelope(t *testing.T, id string, item []byte) entry.Opener {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schema":     "https://example.invalid/schema/vulnerability/cve5/schema-5.2.0.json",
		"identifier": id,
		"item":       json.RawMessage(item),
	})
	require.NoError(t, err)
	return bytesOpener{name: id, contents: b}
}

func openers(ops ...entry.Opener) <-chan entry.Opener {
	ch := make(chan entry.Opener, len(ops))
	for _, o := range ops {
		ch <- o
	}
	close(ch)
	return ch
}

func readCVE5Fixture(t *testing.T, cve string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cna", "cve5", cve+".json"))
	require.NoError(t, err)
	return b
}

func cve5Opener(t *testing.T, cve string) entry.Opener {
	t.Helper()
	return cve5Envelope(t, "2026/"+strings.ToLower(cve), readCVE5Fixture(t, cve))
}

// loadCVE5Fixture decodes an unmodified cvelistV5 record.
func loadCVE5Fixture(t *testing.T, cve string) unmarshal.CVE5Record {
	t.Helper()
	records, err := unmarshal.CVE5Entries(bytes.NewReader(readCVE5Fixture(t, cve)))
	require.NoError(t, err)
	require.Len(t, records, 1)
	return records[0]
}

func newTestIndex(t *testing.T, cves ...string) *Index {
	t.Helper()
	var ops []entry.Opener
	for _, c := range cves {
		ops = append(ops, cve5Opener(t, c))
	}
	idx, err := NewIndex(openers(ops...))
	require.NoError(t, err)
	return idx
}

func TestNewIndex_keepAndSkipRules(t *testing.T) {
	tests := []struct {
		cve  string
		kept bool
		why  string
	}{
		{cve: "CVE-2026-85091", kept: true, why: "cpeApplicability and a purl"},
		{cve: "CVE-2026-59650", kept: true, why: "purls without cpeApplicability"},
		{cve: "CVE-2026-41608", kept: true, why: "collectionURL without a purl"},
		{cve: "CVE-2026-31391", kept: true, why: "cpeApplicability only"},
		{cve: "CVE-2026-13500", kept: false, why: "vendor and product only"},
	}

	var cves []string
	for _, tt := range tests {
		cves = append(cves, tt.cve)
	}
	idx := newTestIndex(t, cves...)

	require.Equal(t, len(tests), idx.Count(), "count includes records that are not kept")
	for _, tt := range tests {
		t.Run(tt.cve, func(t *testing.T) {
			r, ok := idx.Take(tt.cve)
			require.Equal(t, tt.kept, ok, tt.why)
			if ok {
				require.Equal(t, tt.cve, r.CVEMetadata.CVEID)
			}
		})
	}
}

func TestIndex_TakeIsCaseInsensitiveAndConsumes(t *testing.T) {
	idx := newTestIndex(t, "CVE-2026-85091", "CVE-2026-59650")

	r, ok := idx.Take("cve-2026-85091")
	require.True(t, ok)
	require.Equal(t, "CVE-2026-85091", r.CVEMetadata.CVEID)

	_, ok = idx.Take("CVE-2026-00000")
	require.False(t, ok)

	left := idx.Leftovers()
	require.Len(t, left, 1)
	require.Equal(t, "CVE-2026-59650", left[0].CVEMetadata.CVEID)

	// taking again still returns the record, and it stays consumed
	_, ok = idx.Take("CVE-2026-85091")
	require.True(t, ok)
	require.Len(t, idx.Leftovers(), 1)
}

func TestIndex_LeftoversSortedAndPublishedOnly(t *testing.T) {
	// real REJECTED records carry no CNA data, so one real record has its state edited to REJECTED here
	rejected := bytes.Replace(readCVE5Fixture(t, "CVE-2026-53835"), []byte(`"state": "PUBLISHED"`), []byte(`"state": "REJECTED"`), 1)
	require.Contains(t, string(rejected), "REJECTED")

	idx, err := NewIndex(openers(
		cve5Opener(t, "CVE-2026-85091"),
		cve5Envelope(t, "2026/cve-2026-53835", rejected),
		cve5Opener(t, "CVE-2026-41608"),
		cve5Opener(t, "CVE-2026-59650"),
	))
	require.NoError(t, err)
	require.Equal(t, 4, idx.Count())

	var ids []string
	for _, r := range idx.Leftovers() {
		ids = append(ids, r.CVEMetadata.CVEID)
	}
	require.Equal(t, []string{"CVE-2026-41608", "CVE-2026-59650", "CVE-2026-85091"}, ids)
}

func TestNewIndex_badRecordsAreSkippedAndCounted(t *testing.T) {
	idx, err := NewIndex(openers(
		cve5Opener(t, "CVE-2026-85091"),
		bytesOpener{name: "2026/not-an-envelope", contents: []byte(`not json`)},
		cve5Envelope(t, "2026/cve-2026-00001", []byte(`"a string, not a record"`)),
	))
	require.NoError(t, err)
	require.Equal(t, 3, idx.Count())
	require.Len(t, idx.Leftovers(), 1)
}

func TestNewIndex_openFailureIsAnError(t *testing.T) {
	idx, err := NewIndex(openers(bytesOpener{name: "broken", err: io.ErrUnexpectedEOF}))
	require.Error(t, err)
	require.Nil(t, idx)
}

func TestNewIndex_laterDuplicateReplacesEarlier(t *testing.T) {
	idx, err := NewIndex(openers(
		cve5Opener(t, "CVE-2026-85091"),
		cve5Opener(t, "CVE-2026-85091"),
	))
	require.NoError(t, err)
	require.Equal(t, 2, idx.Count())
	require.Len(t, idx.Leftovers(), 1)
}

func TestCPEApplicabilityUsable(t *testing.T) {
	require.False(t, cpeApplicabilityUsable("Linux"))
	require.True(t, cpeApplicabilityUsable("VulnCheck"))
	require.True(t, cpeApplicabilityUsable(""))
}
