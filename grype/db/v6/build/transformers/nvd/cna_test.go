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
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
	"github.com/anchore/grype/grype/db/provider/entry"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
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

// cnaOnly projects a record with the CNA's affected list even when it has an `anchoreadp` container, for the
// table cases that exercise the rules on the CNA's entries. The build selects the `anchoreadp` list instead.
func cnaOnly(r unmarshal.CVE5Record) Projection {
	p := project(r)
	p.Affected = r.Containers.CNA.Affected
	return p
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
		{cve: "CVE-2026-92789", kept: true, why: "anchoreadp cpeApplicability and purl, with nothing usable in the CNA container"},
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
				require.Equal(t, tt.cve, r.ID)
			}
		})
	}
}

func TestIndex_TakeIsCaseInsensitiveAndConsumes(t *testing.T) {
	idx := newTestIndex(t, "CVE-2026-85091", "CVE-2026-59650")

	r, ok := idx.Take("cve-2026-85091")
	require.True(t, ok)
	require.Equal(t, "CVE-2026-85091", r.ID)

	_, ok = idx.Take("CVE-2026-00000")
	require.False(t, ok)

	left := idx.Leftovers()
	require.Len(t, left, 1)
	require.Equal(t, "CVE-2026-59650", left[0].ID)

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
		ids = append(ids, r.ID)
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

func TestProjection_hasData(t *testing.T) {
	purl := []unmarshal.CVE5Affected{{PackageURL: "pkg:pypi/thrift"}}
	productOnly := []unmarshal.CVE5Affected{{Vendor: "Apache", Product: "Thrift"}}
	cpe := []nvd.Configuration{{}}

	require.False(t, Projection{Affected: productOnly}.hasData())
	require.True(t, Projection{Affected: purl}.hasData())
	require.True(t, Projection{Affected: []unmarshal.CVE5Affected{{CollectionURL: "https://pypi.org/"}}}.hasData())
	require.True(t, Projection{CNACPE: cpe}.hasData())
	require.True(t, Projection{ADPCPE: cpe, Affected: productOnly}.hasData(), "anchoreadp cpeApplicability alone is enough")
}

// the records are unmodified from the published dataset
func TestIndex_selectsAffectedList(t *testing.T) {
	tests := []struct {
		name string
		cve  string
		want []wantPackage
	}{
		{
			name: "anchoreadp list replaces a CNA list with the same package",
			cve:  "CVE-2026-41608",
			want: []wantPackage{{"python", "thrift", []wantRange{{"pypi", "< 0.24.0", "0.24.0"}}}},
		},
		{
			name: "anchoreadp list names purls where the CNA names products",
			cve:  "CVE-2026-47392",
			want: []wantPackage{
				{"python", "praisonai", []wantRange{{"pypi", "< 4.6.40", "4.6.40"}}},
				{"python", "praisonaiagents", []wantRange{{"pypi", "< 1.6.40", "1.6.40"}}},
			},
		},
		{
			name: "anchoreadp ranges replace free text versions",
			cve:  "CVE-2025-7783",
			want: []wantPackage{{"npm", "form-data", []wantRange{
				{"npm", "< 2.5.4", "2.5.4"},
				{"npm", ">= 3.0.0, < 3.0.4", "3.0.4"},
				{"npm", ">= 4.0.0, < 4.0.4", "4.0.4"},
			}}},
		},
		{
			name: "the lists are not merged, so the CNA's seata-server gets no row",
			cve:  "CVE-2025-32897",
			want: []wantPackage{{"java-archive", "org.apache.seata:seata-config-core", []wantRange{{"maven", ">= 2.0.0, < 2.3.0", "2.3.0"}}}},
		},
		{
			name: "crate entries come from the anchoreadp list",
			cve:  "CVE-2026-40034",
			want: []wantPackage{
				{"rust-crate", "gitoxide", []wantRange{{"cargo", "< 0.5.21", "0.5.21"}}},
				{"rust-crate", "gix-submodule", []wantRange{{"cargo", "< 0.29.0", "0.29.0"}}},
				{"rust-crate", "gix", []wantRange{{"cargo", "< 0.84.0", "0.84.0"}}},
			},
		},
		{
			name: "a record with no anchoreadp container keeps the CNA's list",
			cve:  "CVE-2026-53424",
			want: []wantPackage{{"hex", "samly", []wantRange{{"hex", ">= 0.3.0", ""}}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cve+" "+tt.name, func(t *testing.T) {
			p, ok := newTestIndex(t, tt.cve).Take(tt.cve)
			require.True(t, ok)
			require.Equal(t, tt.want, summarizeCNAPackages(cnaPackageHandles(p)))
		})
	}
}

// the CNA entry of this record has a collectionURL and no purl, so a purl on the selected entry shows the row came
// from the anchoreadp list
func TestIndex_selectedListIsAnchoreADPForCVE202666053(t *testing.T) {
	p, ok := newTestIndex(t, "CVE-2026-66053").Take("CVE-2026-66053")
	require.True(t, ok)

	require.Len(t, p.Affected, 1)
	require.Equal(t, "pkg:pypi/thrift", p.Affected[0].PackageURL)
	require.Equal(t, []wantPackage{
		{"python", "thrift", []wantRange{{"pypi", "< 0.24.0", "0.24.0"}}},
	}, summarizeCNAPackages(cnaPackageHandles(p)))
}

func TestProjection_CPESource(t *testing.T) {
	published := func(t *testing.T, cve string) Projection {
		t.Helper()
		p, ok := newTestIndex(t, cve).Take(cve)
		require.True(t, ok)
		return p
	}
	criteria := func(cfgs []nvd.Configuration) (out []string) {
		for _, c := range cfgs {
			for _, n := range c.Nodes {
				for _, m := range n.CpeMatch {
					out = append(out, m.Criteria)
				}
			}
		}
		return out
	}

	t.Run("anchoreadp when the CNA has none", func(t *testing.T) {
		p := published(t, "CVE-2026-92789")
		require.Empty(t, p.CNACPE)
		require.Equal(t, []string{
			"cpe:2.3:a:graylog:graylog:*:*:*:*:*:maven:*:*",
			"cpe:2.3:a:org.graylog2:graylog2-server:*:*:*:*:*:maven:*:*",
		}, criteria(p.CPESource()))
	})

	t.Run("anchoreadp over a different CNA list", func(t *testing.T) {
		p := published(t, "CVE-2026-0229")
		require.NotEmpty(t, p.CNACPE)
		require.NotEmpty(t, p.ADPCPE)
		require.NotEqual(t, p.CNACPE, p.ADPCPE)
		require.Equal(t, p.ADPCPE, p.CPESource())
	})

	t.Run("the CNA's when there is no anchoreadp one", func(t *testing.T) {
		p := published(t, "CVE-2026-85091")
		require.Empty(t, p.ADPCPE)
		require.Equal(t, p.CNACPE, p.CPESource())
		require.NotEmpty(t, p.CPESource())
	})

	t.Run("an excluded assigner's CNA list is dropped but anchoreadp's is used", func(t *testing.T) {
		cna, adp := []nvd.Configuration{{}}, []nvd.Configuration{{Nodes: []nvd.Node{{}}}}
		require.Nil(t, Projection{Assigner: "Linux", CNACPE: cna}.CPESource())
		require.Equal(t, adp, Projection{Assigner: "Linux", CNACPE: cna, ADPCPE: adp}.CPESource())
	})
}

func TestCPEApplicabilityUsable(t *testing.T) {
	require.False(t, cpeApplicabilityUsable("Linux"))
	require.True(t, cpeApplicabilityUsable("VulnCheck"))
	require.True(t, cpeApplicabilityUsable(""))
}

type wantRange struct {
	versionType string
	constraint  string
	fix         string
}

type wantPackage struct {
	ecosystem string
	name      string
	ranges    []wantRange
}

func summarizeCNAPackages(handles []db.AffectedPackageHandle) []wantPackage {
	var out []wantPackage
	for _, h := range handles {
		p := wantPackage{ecosystem: h.Package.Ecosystem, name: h.Package.Name}
		for _, r := range h.BlobValue.Ranges {
			wr := wantRange{versionType: r.Version.Type, constraint: r.Version.Constraint}
			if r.Fix != nil {
				wr.fix = r.Fix.Version
			}
			p.ranges = append(p.ranges, wr)
		}
		out = append(out, p)
	}
	return out
}

// the cases are unmodified cvelistV5 records, so a change in how an entry is read shows up as a failure here
func TestCNAPackageHandles_fixtures(t *testing.T) {
	tests := []struct {
		name string
		cve  string
		want []wantPackage
	}{
		// supported-ecosystems
		{
			name: "purl type in the table is compared fuzzily",
			cve:  "CVE-2026-40034",
			want: []wantPackage{
				{"rust-crate", "gitoxide", []wantRange{{"cargo", "< 0.5.21", "0.5.21"}}},
				{"rust-crate", "gix", []wantRange{{"cargo", "< 0.29.0", "0.29.0"}}},
				{"rust-crate", "gix", []wantRange{{"cargo", "< 0.84.0", "0.84.0"}}},
			},
		},
		{
			name: "registry host with a path",
			cve:  "CVE-2025-63041",
			want: []wantPackage{
				{"wordpress-plugin", "forget-about-shortcode-buttons", []wantRange{{"wordpress-plugin", "<= 2.1.3", ""}}},
			},
		},
		{
			name: "hex purl beside pkg:github entries",
			cve:  "CVE-2026-53424",
			want: []wantPackage{
				{"hex", "samly", []wantRange{{"hex", ">= 0.3.0", ""}}},
			},
		},
		{
			name: "wordpress theme",
			cve:  "CVE-2025-22792",
		},
		{
			name: "pkg:github purl only",
			cve:  "CVE-2026-85091",
		},
		{
			name: "vendor and product only",
			cve:  "CVE-2026-13500",
		},
		{
			name: "linux kernel entries have no locator",
			cve:  "CVE-2026-31391",
		},
		{
			name: "collectionURL with a trailing slash",
			cve:  "CVE-2026-41608",
			want: []wantPackage{
				{"python", "thrift", []wantRange{{"pypi", "< 0.24.0", "0.24.0"}}},
			},
		},
		{
			name: "collectionURL without a trailing slash",
			cve:  "CVE-2026-66053",
			want: []wantPackage{
				{"python", "thrift", []wantRange{{"pypi", "< 0.24.0", "0.24.0"}}},
			},
		},
		{
			name: "maven purls, where the purl wins over packageName",
			cve:  "CVE-2026-59650",
			want: []wantPackage{
				{"java-archive", "org.bouncycastle:bcprov-jdk18on", []wantRange{{"maven", "< 1.85", "1.85"}}},
				{"java-archive", "org.bouncycastle:bcprov-lts8on", []wantRange{{"maven", ">= 2.73.0, < 2.73.12", "2.73.12"}}},
			},
		},
		{
			name: "composer purl keeps the vendor, as the github transformer names the package",
			cve:  "CVE-2026-72778",
			want: []wantPackage{
				{"php-composer", "craftcms/cms", []wantRange{{"composer", ">= 5.0.0-RC1, < 5.10.6", "5.10.6"}}},
				{"php-composer", "craftcms/cms", []wantRange{{"composer", ">= 4.0.0-RC1, < 4.18.2", "4.18.2"}}},
			},
		},
		{
			name: "several ranges for one package",
			cve:  "CVE-2026-8763",
			want: []wantPackage{
				{"java-archive", "org.bouncycastle:bcprov-jdk18on", []wantRange{{"maven", "< 1.85", "1.85"}}},
				{"java-archive", "org.bouncycastle:bcprov-lts8on", []wantRange{{"maven", ">= 2.73.0, < 2.73.12", "2.73.12"}}},
				{"java-archive", "org.bouncycastle:bc-fips", []wantRange{
					{"maven", ">= 1.0.0, < 1.0.2.7", "1.0.2.7"},
					{"maven", ">= 2.0.0, < 2.0.2", "2.0.2"},
					{"maven", ">= 2.1.0, < 2.1.3", "2.1.3"},
				}},
			},
		},

		// ranges-no-broader-than-stated
		{
			name: "lower bound and exclusive upper bound, from a group:artifact packageName",
			cve:  "CVE-2025-32897",
			want: []wantPackage{
				{"java-archive", "org.apache.seata:seata-server", []wantRange{{"maven", ">= 2.0.0, < 2.3.0", "2.3.0"}}},
			},
		},
		{
			name: "change above the upper bound is ignored",
			cve:  "CVE-2025-43839",
			want: []wantPackage{
				{"wordpress-plugin", "bp-messages-tool", []wantRange{{"wordpress-plugin", "<= 2.2", ""}}},
			},
		},
		{
			name: "change inside a range drops that item only",
			cve:  "CVE-2026-2415",
			want: []wantPackage{
				{"python", "pretix", []wantRange{
					{"pypi", ">= 4.16.0, < 2025.9.0", "2025.9.0"},
					{"pypi", ">= 2026.1.0, < 2026.1.1", "2026.1.1"},
				}},
			},
		},
		{
			name: "unaffected item adds nothing",
			cve:  "CVE-2026-53835",
			want: []wantPackage{
				{"npm", "openclaw", []wantRange{{"npm", "< 2026.5.6", "2026.5.6"}}},
			},
		},
		{
			name: "exact version",
			cve:  "CVE-2025-22624",
			want: []wantPackage{
				{"wordpress-plugin", "foogallery", []wantRange{{"wordpress-plugin", "= 2.4.29", ""}}},
			},
		},
		{
			name: "placeholder with no bound",
			cve:  "CVE-2026-25904",
		},
		{
			name: "range written as free text",
			cve:  "CVE-2025-7783",
		},
		{
			name: "default status affected",
			cve:  "CVE-2025-47909",
		},
	}

	for _, tt := range tests {
		t.Run(tt.cve+" "+tt.name, func(t *testing.T) {
			got := summarizeCNAPackages(cnaPackageHandles(cnaOnly(loadCVE5Fixture(t, tt.cve))))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestCNAPackageHandles_noUpperBoundIsNotAFix(t *testing.T) {
	// CVE-2026-53424's hex entry is {version "0.3.0", lessThan "*"}
	handles := cnaPackageHandles(cnaOnly(loadCVE5Fixture(t, "CVE-2026-53424")))
	require.Len(t, handles, 1)
	require.Len(t, handles[0].BlobValue.Ranges, 1)
	require.Nil(t, handles[0].BlobValue.Ranges[0].Fix)
	require.Equal(t, []string{"CVE-2026-53424"}, handles[0].BlobValue.CVEs)
}

func TestCNAPackageHandles_unknownFormatTypesCompareFuzzily(t *testing.T) {
	for _, tc := range []struct{ cve, versionType string }{
		{"CVE-2026-40034", "cargo"},
		{"CVE-2025-63041", "wordpress-plugin"},
	} {
		handles := cnaPackageHandles(cnaOnly(loadCVE5Fixture(t, tc.cve)))
		require.NotEmpty(t, handles)
		for _, h := range handles {
			for _, r := range h.BlobValue.Ranges {
				require.Equal(t, tc.versionType, r.Version.Type)
				require.Equal(t, version.UnknownFormat, version.ParseFormat(r.Version.Type))
			}
		}
	}
}

func TestCNAPackageHandles_locator(t *testing.T) {
	affected := func(purl, collectionURL, packageName string) Projection {
		var r Projection
		r.ID = "CVE-2026-00001"
		r.Affected = []unmarshal.CVE5Affected{{
			PackageURL:    purl,
			CollectionURL: collectionURL,
			PackageName:   packageName,
			Versions:      []unmarshal.CVE5Version{{Version: "0", LessThan: "2.0.0", Status: "affected"}},
		}}
		return r
	}

	tests := []struct {
		name string
		rec  Projection
		want []wantPackage
	}{
		{
			name: "purl wins over collectionURL and packageName",
			rec:  affected("pkg:pypi/real-name", "https://registry.npmjs.org/", "other"),
			want: []wantPackage{{"python", "real-name", []wantRange{{"pypi", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "scheme, host case and path are ignored",
			rec:  affected("", "HTTP://Registry.NPMJS.org/some/path", "left-pad"),
			want: []wantPackage{{"npm", "left-pad", []wantRange{{"npm", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "collectionURL without a scheme",
			rec:  affected("", "crates.io", "serde"),
			want: []wantPackage{{"rust-crate", "serde", []wantRange{{"cargo", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "scoped npm package from a registry host",
			rec:  affected("", "https://www.npmjs.com/", "@scope/name"),
			want: []wantPackage{{"npm", "@scope/name", []wantRange{{"npm", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "go module path from a registry host",
			rec:  affected("", "https://pkg.go.dev", "github.com/example/mod"),
			want: []wantPackage{{"go-module", "github.com/example/mod", []wantRange{{"golang", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "go module purl keeps its namespace",
			rec:  affected("pkg:golang/github.com/example/mod", "", ""),
			want: []wantPackage{{"go-module", "github.com/example/mod", []wantRange{{"golang", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "pypi names are normalized",
			rec:  affected("pkg:pypi/Some_Package", "", ""),
			want: []wantPackage{{"python", "some-package", []wantRange{{"pypi", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "swift purl with no version",
			rec:  affected("pkg:swift/github.com/apple/swift-nio", "", ""),
			want: []wantPackage{{"swift", "swift-nio", []wantRange{{"swift", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "pub purl",
			rec:  affected("pkg:pub/http", "", ""),
			want: []wantPackage{{"dart-pub", "http", []wantRange{{"pub", "< 2.0.0", "2.0.0"}}}},
		},
		{
			name: "purl type not in the table",
			rec:  affected("pkg:cpan/Some-Module", "", ""),
		},
		{
			name: "pkg:github purl on github.com",
			rec:  affected("pkg:github/example/repo", "https://github.com", "example/repo"),
		},
		{
			name: "host not in the table",
			rec:  affected("", "https://example.com/pypi", "thrift"),
		},
		{
			name: "wordpress themes are not plugins",
			rec:  affected("", "https://wordpress.org/themes", "some-theme"),
		},
		{
			name: "wordpress.org with no path",
			rec:  affected("", "https://wordpress.org", "something"),
		},
		{
			name: "maven packageName without a group",
			rec:  affected("", "https://repo1.maven.org/maven2", "artifact-only"),
		},
		{
			name: "maven purl without a group",
			rec:  affected("pkg:maven/artifact-only", "", ""),
		},
		{
			name: "registry host without a packageName",
			rec:  affected("", "https://pypi.org/", ""),
		},
		{
			name: "unparseable purl falls back to the collectionURL",
			rec:  affected("not a purl", "https://pypi.org/", "thrift"),
			want: []wantPackage{{"python", "thrift", []wantRange{{"pypi", "< 2.0.0", "2.0.0"}}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, summarizeCNAPackages(cnaPackageHandles(tt.rec)))
		})
	}
}

func TestCNARanges_rules(t *testing.T) {
	item := func(v, lt, lte string, changes ...unmarshal.CVE5Change) unmarshal.CVE5Version {
		return unmarshal.CVE5Version{Version: v, LessThan: lt, LessThanOrEqual: lte, Status: "affected", Changes: changes}
	}

	tests := []struct {
		name  string
		purl  string
		items []unmarshal.CVE5Version
		want  []wantRange
	}{
		{
			name:  "lower bound with inclusive upper bound",
			purl:  "npm",
			items: []unmarshal.CVE5Version{item("1.0.0", "", "1.5.0")},
			want:  []wantRange{{"npm", ">= 1.0.0, <= 1.5.0", ""}},
		},
		{
			name:  "placeholder lower bound with exclusive upper bound",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("n/a", "3.0", "")},
			want:  []wantRange{{"pypi", "< 3.0", "3.0"}},
		},
		{
			name:  "star upper bound after a placeholder lower bound",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("0", "*", "")},
		},
		{
			name:  "star inclusive upper bound",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "", "*")},
			want:  []wantRange{{"pypi", ">= 1.0", ""}},
		},
		{
			name:  "any change when there is no upper bound",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "*", "", unmarshal.CVE5Change{At: "9.9", Status: "unaffected"})},
		},
		{
			name:  "change at the upper bound is ignored",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "2.0", "", unmarshal.CVE5Change{At: "2.0", Status: "unaffected"})},
			want:  []wantRange{{"pypi", ">= 1.0, < 2.0", "2.0"}},
		},
		{
			name:  "change below the upper bound",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "2.0", "", unmarshal.CVE5Change{At: "1.5", Status: "unaffected"})},
		},
		{
			name:  "change that cannot be compared",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "2.0", "", unmarshal.CVE5Change{At: "not a version", Status: "unaffected"})},
		},
		{
			name:  "lessThan and lessThanOrEqual together",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "2.0", "2.1")},
		},
		{
			name: "unspecified and unknown versions",
			purl: "pypi",
			items: []unmarshal.CVE5Version{
				item("unspecified", "2.0", ""),
				item("unknown", "", ""),
				item("1.0", "unspecified", ""),
			},
		},
		{
			name: "free text and star inside a version",
			purl: "pypi",
			items: []unmarshal.CVE5Version{
				item(">= 1.0", "", ""),
				item("1.*", "", ""),
				item("1.0", "2.*", ""),
				item("1.0,2.0", "", ""),
				item("1.0=", "", ""),
			},
		},
		{
			name: "status other than affected",
			purl: "pypi",
			items: []unmarshal.CVE5Version{
				{Version: "1.0", LessThan: "2.0", Status: "unaffected"},
				{Version: "1.0", LessThan: "2.0", Status: "unknown"},
			},
		},
		{
			name:  "a constraint that fails validation drops only its item",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{item("1.0", "2.0", ""), item("1.0", "", "foo")},
			want:  []wantRange{{"pypi", ">= 1.0, < 2.0", "2.0"}},
		},
		{
			name:  "versionType does not affect the mapping",
			purl:  "pypi",
			items: []unmarshal.CVE5Version{{Version: "1.0", LessThan: "2.0", Status: "affected", VersionType: "git"}},
			want:  []wantRange{{"pypi", ">= 1.0, < 2.0", "2.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []wantRange
			for _, r := range cnaRanges("CVE-2026-00001", tt.purl, tt.items) {
				wr := wantRange{versionType: r.Version.Type, constraint: r.Version.Constraint}
				if r.Fix != nil {
					wr.fix = r.Fix.Version
				}
				got = append(got, wr)
			}
			require.Equal(t, tt.want, got)
		})
	}
}
