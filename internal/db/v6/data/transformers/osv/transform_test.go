package osv

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
)

var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState() provider.State {
	return provider.State{
		Provider:  "osv",
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider() *v6.Provider {
	return &v6.Provider{
		ID:           "osv",
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	entries, err := unmarshal.OSVVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func affectedPkgSlice(a ...v6.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func TestTransform(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		want        []transformers.RelatedEntries
	}{
		{
			name:        "Apache 2020-11984",
			fixturePath: "test-fixtures/BIT-apache-2020-11984.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &v6.VulnerabilityHandle{
					Name:          "BIT-apache-2020-11984",
					Status:        v6.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  &[]time.Time{time.Date(2025, time.January, 17, 15, 26, 01, 971000000, time.UTC)}[0],
					PublishedDate: &[]time.Time{time.Date(2024, time.March, 6, 10, 57, 57, 770000000, time.UTC)}[0],
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "BIT-apache-2020-11984",
						Description: "Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE",
						References: []v6.Reference{{
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/1",
							Tags: []string{"WEB"},
						}, {
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/10",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-11984"},
						Severities: []v6.Severity{{
							Scheme: v6.SeveritySchemeCVSS,
							Value: v6.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					v6.AffectedPackageHandle{
						Package: &v6.Package{
							Name:      "apache",
							Ecosystem: "Bitnami",
						},
						BlobValue: &v6.AffectedPackageBlob{
							CVEs: []string{"CVE-2020-11984"},
							Ranges: []v6.AffectedRange{{
								Version: v6.AffectedVersion{
									Type:       "semver",
									Constraint: ">=2.4.32,<=2.4.43",
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "Node 2020-8201",
			fixturePath: "test-fixtures/BIT-node-2020-8201.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &v6.VulnerabilityHandle{
					Name:          "BIT-node-2020-8201",
					Status:        v6.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  &[]time.Time{time.Date(2024, time.March, 6, 11, 25, 28, 861000000, time.UTC)}[0],
					PublishedDate: &[]time.Time{time.Date(2024, time.March, 6, 11, 8, 9, 371000000, time.UTC)}[0],
					BlobValue: &v6.VulnerabilityBlob{
						ID:          "BIT-node-2020-8201",
						Description: "Node.js < 12.18.4 and < 14.11 can be exploited to perform HTTP desync attacks and deliver malicious payloads to unsuspecting users. The payloads can be crafted by an attacker to hijack user sessions, poison cookies, perform clickjacking, and a multitude of other attacks depending on the architecture of the underlying system. The attack was possible due to a bug in processing of carrier-return symbols in the HTTP header names.",
						References: []v6.Reference{{
							URL:  "https://nodejs.org/en/blog/vulnerability/september-2020-security-releases/",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://security.gentoo.org/glsa/202101-07",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-8201"},
						Severities: []v6.Severity{{
							Scheme: v6.SeveritySchemeCVSS,
							Value: v6.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					v6.AffectedPackageHandle{
						Package: &v6.Package{
							Name:      "node",
							Ecosystem: "Bitnami",
						},
						BlobValue: &v6.AffectedPackageBlob{
							CVEs: []string{"CVE-2020-8201"},
							Ranges: []v6.AffectedRange{{
								Version: v6.AffectedVersion{
									Type:       "semver",
									Constraint: ">=12.0.0,<12.18.4",
								},
								Fix: &v6.Fix{
									Version: "12.18.4",
									State:   v6.FixedStatus,
								},
							}, {
								Version: v6.AffectedVersion{
									Type:       "semver",
									Constraint: ">=14.0.0,<14.11.0",
								},
								Fix: &v6.Fix{
									Version: "14.11.0",
									State:   v6.FixedStatus,
								},
							}},
						},
					},
				),
			}},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			vulns := loadFixture(t, test.fixturePath)
			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState())
				require.NoError(t, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(t, ok)
					actual = append(actual, e)
				}
			}

			if diff := cmp.Diff(test.want, actual); diff != "" {
				t.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
func Test_getGrypeRangesFromRange(t *testing.T) {
	tests := []struct {
		name string
		rnge models.Range
		want []v6.AffectedRange
	}{
		{
			name: "single range with 'fixed' status",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					Fixed: "0.0.5",
				}},
			},
			want: []v6.AffectedRange{{
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &v6.Fix{
					Version: "0.0.5",
					State:   v6.FixedStatus,
				},
			}},
		},
		{
			name: "single range with 'last affected' status",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []v6.AffectedRange{{
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: ">=0.0.1,<=0.0.5",
				},
			}},
		},
		{
			name: "single range with no 'fixed' or 'last affected' status",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}},
			},
			want: []v6.AffectedRange{{
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: ">=0.0.1",
				},
			}},
		},
		{
			name: "single range introduced with '0'",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []v6.AffectedRange{{
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: "<=0.0.5",
				},
			}},
		},
		{
			name: "multiple ranges",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					Fixed: "0.0.5",
				}, {
					Introduced: "1.0.1",
				}, {
					Fixed: "1.0.5",
				}},
			},
			want: []v6.AffectedRange{{
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &v6.Fix{
					Version: "0.0.5",
					State:   v6.FixedStatus,
				},
			}, {
				Version: v6.AffectedVersion{
					Type:       "semver",
					Constraint: ">=1.0.1,<1.0.5",
				},
				Fix: &v6.Fix{
					Version: "1.0.5",
					State:   v6.FixedStatus,
				},
			},
			},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			if got := getGrypeRangesFromRange(test.rnge); !reflect.DeepEqual(got, test.want) {
				t.Errorf("getGrypeRangesFromRange() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_getPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.Package
		want *v6.Package
	}{
		{
			name: "valid package",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &v6.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty purl",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "",
			},
			want: &v6.Package{
				Name:      "apache",
				Ecosystem: "Bitnami",
			},
		},
		{
			name: "package with empty ecosystem",
			pkg: models.Package{
				Ecosystem: "",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &v6.Package{
				Name:      "apache",
				Ecosystem: "",
			},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got := getPackage(test.pkg)
			if got.Name != test.want.Name {
				t.Errorf("getPackage() got name = %v, want %v", got.Name, test.want.Name)
			}
			if got.Ecosystem != test.want.Ecosystem {
				t.Errorf("getPackage() got ecosystem = %v, want %v", got.Ecosystem, test.want.Ecosystem)
			}
		})
	}
}

func Test_extractCVSSInfo(t *testing.T) {
	tests := []struct {
		name        string
		cvss        string
		wantVersion string
		wantVector  string
		wantErr     bool
	}{
		{
			name:        "valid cvss",
			cvss:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "3.1",
			wantVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:     false,
		},
		{
			name:        "invalid cvss",
			cvss:        "foo:3.1/bar",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "empty cvss",
			cvss:        "",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
		{
			name:        "invalid cvss version",
			cvss:        "CVSS:foo/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "",
			wantVector:  "",
			wantErr:     true,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			gotVersion, gotVector, err := extractCVSSInfo(test.cvss)
			if (err != nil) != test.wantErr {
				t.Errorf("extractCVSSInfo() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if gotVersion != test.wantVersion {
				t.Errorf("extractCVSSInfo() got version = %v, want %v", gotVersion, test.wantVersion)
			}
			if gotVector != test.wantVector {
				t.Errorf("extractCVSSInfo() got vector = %v, want %v", gotVector, test.wantVector)
			}
		})
	}
}
