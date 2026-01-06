package osv

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/tests"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
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

func expectedProvider() *grypeDB.Provider {
	return &grypeDB.Provider{
		ID:           "osv",
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func timeRef(t time.Time) *time.Time {
	return &t
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.OSVVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func affectedPkgSlice(a ...grypeDB.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func unaffectedPkgSlice(u ...grypeDB.UnaffectedPackageHandle) []any {
	var r []any
	for _, v := range u {
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
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:          "BIT-apache-2020-11984",
					Status:        grypeDB.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.January, 17, 15, 26, 01, 971000000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.March, 6, 10, 57, 57, 770000000, time.UTC)),
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "BIT-apache-2020-11984",
						Description: "Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE",
						References: []grypeDB.Reference{{
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/1",
							Tags: []string{"WEB"},
						}, {
							URL:  "http://www.openwall.com/lists/oss-security/2020/08/08/10",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-11984"},
						Severities: []grypeDB.Severity{{
							Scheme: grypeDB.SeveritySchemeCVSS,
							Value: grypeDB.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					grypeDB.AffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "apache",
							Ecosystem: "Bitnami",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"CVE-2020-11984"},
							Ranges: []grypeDB.Range{{
								Version: grypeDB.Version{
									Type:       "bitnami",
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
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:          "BIT-node-2020-8201",
					Status:        grypeDB.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2024, time.March, 6, 11, 25, 28, 861000000, time.UTC)),
					PublishedDate: timeRef(time.Date(2024, time.March, 6, 11, 8, 9, 371000000, time.UTC)),
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "BIT-node-2020-8201",
						Description: "Node.js < 12.18.4 and < 14.11 can be exploited to perform HTTP desync attacks and deliver malicious payloads to unsuspecting users. The payloads can be crafted by an attacker to hijack user sessions, poison cookies, perform clickjacking, and a multitude of other attacks depending on the architecture of the underlying system. The attack was possible due to a bug in processing of carrier-return symbols in the HTTP header names.",
						References: []grypeDB.Reference{{
							URL:  "https://nodejs.org/en/blog/vulnerability/september-2020-security-releases/",
							Tags: []string{"WEB"},
						}, {
							URL:  "https://security.gentoo.org/glsa/202101-07",
							Tags: []string{"WEB"},
						}},
						Aliases: []string{"CVE-2020-8201"},
						Severities: []grypeDB.Severity{{
							Scheme: grypeDB.SeveritySchemeCVSS,
							Value: grypeDB.CVSSSeverity{
								Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
								Version: "3.1",
							},
						}},
					},
				},
				Related: affectedPkgSlice(
					grypeDB.AffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "node",
							Ecosystem: "Bitnami",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"CVE-2020-8201"},
							Ranges: []grypeDB.Range{{
								Version: grypeDB.Version{
									Type:       "bitnami",
									Constraint: ">=12.0.0,<12.18.4",
								},
								Fix: &grypeDB.Fix{
									Version: "12.18.4",
									State:   grypeDB.FixedStatus,
									Detail: &grypeDB.FixDetail{
										Available: &grypeDB.FixAvailability{
											Date: timeRef(time.Date(2020, time.September, 15, 0, 0, 0, 0, time.UTC)),
											Kind: "first-observed",
										},
									},
								},
							}, {
								Version: grypeDB.Version{
									Type:       "bitnami",
									Constraint: ">=14.0.0,<14.11.0",
								},
								Fix: &grypeDB.Fix{
									Version: "14.11.0",
									State:   grypeDB.FixedStatus,
									Detail: &grypeDB.FixDetail{
										Available: &grypeDB.FixAvailability{
											Date: timeRef(time.Date(2020, time.September, 15, 0, 0, 0, 0, time.UTC)),
											Kind: "first-observed",
										},
									},
								},
							}},
						},
					},
				),
			}},
		},
		{
			name:        "AlmaLinux Advisory",
			fixturePath: "test-fixtures/ALSA-2025-7467.json",
			want: []transformers.RelatedEntries{{
				VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
					Name:          "ALSA-2025:7467",
					Status:        grypeDB.VulnerabilityActive,
					ProviderID:    "osv",
					Provider:      expectedProvider(),
					ModifiedDate:  timeRef(time.Date(2025, time.July, 2, 12, 50, 6, 0, time.UTC)),
					PublishedDate: timeRef(time.Date(2025, time.May, 13, 0, 0, 0, 0, time.UTC)),
					BlobValue: &grypeDB.VulnerabilityBlob{
						ID:          "ALSA-2025:7467",
						Description: "The skopeo command lets you inspect images from container image registries.",
						References: []grypeDB.Reference{{
							ID:   "ALSA-2025:7467",
							URL:  "https://errata.almalinux.org/10/ALSA-2025-7467.html",
							Tags: []string{"ADVISORY"},
						}},
						Aliases:    []string{"CVE-2025-27144"},
						Severities: nil,
					},
				},
				Related: unaffectedPkgSlice(
					grypeDB.UnaffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "skopeo",
							Ecosystem: "rpm",
						},
						OperatingSystem: &grypeDB.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []grypeDB.Range{{
								Version: grypeDB.Version{
									Type:       "ecosystem",
									Constraint: ">= 2:1.18.1-1.el10_0",
								},
								Fix: &grypeDB.Fix{
									Version: "2:1.18.1-1.el10_0",
									State:   grypeDB.FixedStatus,
								},
							}},
						},
					},
					grypeDB.UnaffectedPackageHandle{
						Package: &grypeDB.Package{
							Name:      "skopeo-tests",
							Ecosystem: "rpm",
						},
						OperatingSystem: &grypeDB.OperatingSystem{
							Name:         "almalinux",
							MajorVersion: "10",
						},
						BlobValue: &grypeDB.PackageBlob{
							CVEs: []string{"CVE-2025-27144"},
							Ranges: []grypeDB.Range{{
								Version: grypeDB.Version{
									Type:       "ecosystem",
									Constraint: ">= 2:1.18.1-1.el10_0",
								},
								Fix: &grypeDB.Fix{
									Version: "2:1.18.1-1.el10_0",
									State:   grypeDB.FixedStatus,
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
		name      string
		rnge      models.Range
		ecosystem string
		want      []grypeDB.Range
	}{
		{
			name:      "single range with 'fixed' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					Fixed: "0.0.5",
				}},
			},
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &grypeDB.Fix{
					Version: "0.0.5",
					State:   grypeDB.FixedStatus,
				},
			}},
		},
		{
			name:      "single range with 'last affected' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<=0.0.5",
				},
			}},
		},
		{
			name:      "single range with no 'fixed' or 'last affected' status",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0.0.1",
				}},
			},
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=0.0.1",
				},
			}},
		},
		{
			name:      "single range introduced with '0'",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "0",
				}, {
					LastAffected: "0.0.5",
				}},
			},
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: "<=0.0.5",
				},
			}},
		},
		{
			name:      "multiple ranges",
			ecosystem: "npm",
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
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=0.0.1,<0.0.5",
				},
				Fix: &grypeDB.Fix{
					Version: "0.0.5",
					State:   grypeDB.FixedStatus,
				},
			}, {
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=1.0.1,<1.0.5",
				},
				Fix: &grypeDB.Fix{
					Version: "1.0.5",
					State:   grypeDB.FixedStatus,
				},
			},
			},
		},
		{
			name:      "single range with database-specific fix availability",
			ecosystem: "npm",
			rnge: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{{
					Introduced: "1.0.0",
				}, {
					Fixed: "1.2.3",
				}},
				DatabaseSpecific: map[string]interface{}{
					"anchore": map[string]interface{}{
						"fixes": []interface{}{
							map[string]interface{}{
								"version": "1.2.3",
								"date":    "2023-06-15",
								"kind":    "first-observed",
							},
						},
					},
				},
			},
			want: []grypeDB.Range{{
				Version: grypeDB.Version{
					Type:       "semver",
					Constraint: ">=1.0.0,<1.2.3",
				},
				Fix: &grypeDB.Fix{
					Version: "1.2.3",
					State:   grypeDB.FixedStatus,
					Detail: &grypeDB.FixDetail{
						Available: &grypeDB.FixAvailability{
							Date: timeRef(time.Date(2023, time.June, 15, 0, 0, 0, 0, time.UTC)),
							Kind: "first-observed",
						},
					},
				},
			}},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			if got := getGrypeRangesFromRange(test.rnge, test.ecosystem); !reflect.DeepEqual(got, test.want) {
				t.Errorf("getGrypeRangesFromRange() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_getPackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.Package
		want *grypeDB.Package
	}{
		{
			name: "valid package",
			pkg: models.Package{
				Ecosystem: "Bitnami",
				Name:      "apache",
				Purl:      "pkg:bitnami/apache",
			},
			want: &grypeDB.Package{
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
			want: &grypeDB.Package{
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
			want: &grypeDB.Package{
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

func Test_extractRpmModularity(t *testing.T) {
	tests := []struct {
		name     string
		affected models.Affected
		want     string
	}{
		{
			name: "with rpm_modularity",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "mariadb:10.3",
				},
			},
			want: "mariadb:10.3",
		},
		{
			name: "no ecosystem_specific",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			want: "",
		},
		{
			name: "no rpm_modularity key",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"other_key": "some_value",
				},
			},
			want: "",
		},
		{
			name: "rpm_modularity not string",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": 123,
				},
			},
			want: "",
		},
		{
			name: "nodejs modularity",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "nodejs:16",
				},
			},
			want: "nodejs:16",
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			got := extractRpmModularity(test.affected)
			if got != test.want {
				t.Errorf("extractRpmModularity() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_getPackageQualifiers(t *testing.T) {
	tests := []struct {
		name     string
		affected models.Affected
		cpes     any
		withCPE  bool
		want     *grypeDB.PackageQualifiers
	}{
		{
			name: "with rpm_modularity only",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "mariadb:10.3",
				},
			},
			cpes:    nil,
			withCPE: false,
			want: &grypeDB.PackageQualifiers{
				RpmModularity: stringRef("mariadb:10.3"),
			},
		},
		{
			name: "with CPE only",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			cpes:    []string{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			withCPE: true,
			want: &grypeDB.PackageQualifiers{
				PlatformCPEs: []string{"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"},
			},
		},
		{
			name: "with both rpm_modularity and CPE",
			affected: models.Affected{
				EcosystemSpecific: map[string]interface{}{
					"rpm_modularity": "nodejs:16",
				},
			},
			cpes:    []string{"cpe:2.3:a:nodejs:nodejs:*:*:*:*:*:*:*:*"},
			withCPE: true,
			want: &grypeDB.PackageQualifiers{
				PlatformCPEs:  []string{"cpe:2.3:a:nodejs:nodejs:*:*:*:*:*:*:*:*"},
				RpmModularity: stringRef("nodejs:16"),
			},
		},
		{
			name: "no qualifiers",
			affected: models.Affected{
				EcosystemSpecific: nil,
			},
			cpes:    nil,
			withCPE: false,
			want:    nil,
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			got := getPackageQualifiers(test.affected, test.cpes, test.withCPE)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("getPackageQualifiers() = %v, want %v", got, test.want)
			}
		})
	}
}

func stringRef(s string) *string {
	return &s
}
