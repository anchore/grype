package os

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/testutil"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
)

var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState(name string) provider.State {
	return provider.State{
		Provider:  name,
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider(name string) *db.Provider {
	return &db.Provider{
		ID:           name,
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func TestTransform(t *testing.T) {

	alpineOS := &db.OperatingSystem{
		Name:         "alpine",
		ReleaseID:    "alpine",
		MajorVersion: "3",
		MinorVersion: "9",
	}

	amazonOS := &db.OperatingSystem{
		Name:         "amazonlinux",
		ReleaseID:    "amzn",
		MajorVersion: "2",
	}
	azure3OS := &db.OperatingSystem{
		Name:         "azurelinux",
		ReleaseID:    "azurelinux",
		MajorVersion: "3",
		MinorVersion: "0", // TODO: is this right?
	}
	debian8OS := &db.OperatingSystem{
		Name:         "debian",
		ReleaseID:    "debian",
		MajorVersion: "8",
		Codename:     "jessie",
	}

	mariner2OS := &db.OperatingSystem{
		Name:         "mariner",
		ReleaseID:    "mariner",
		MajorVersion: "2",
		MinorVersion: "0", // TODO: is this right?
	}
	ol8OS := &db.OperatingSystem{
		Name:         "oraclelinux",
		ReleaseID:    "ol",
		MajorVersion: "8",
	}
	rhel8OS := &db.OperatingSystem{
		Name:         "redhat",
		ReleaseID:    "rhel",
		MajorVersion: "8",
	}
	tests := []struct {
		name     string
		provider string
		want     []transformers.RelatedEntries
	}{
		{
			name:     "test-fixtures/alpine-3.9.json",
			provider: "alpine",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2018-19967",
						Status:     "active",
						ProviderID: "alpine",
						Provider:   expectedProvider("alpine"),
						BlobValue: &db.VulnerabilityBlob{
							ID: "CVE-2018-19967",
							References: []db.Reference{
								{
									URL: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: alpineOS,
							Package:         &db.Package{Ecosystem: "apk", Name: "xen"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "apk", Constraint: "< 4.11.1-r0"},
										Fix: &db.Fix{
											Version: "4.11.1-r0",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												Available: &db.FixAvailability{
													Date: timeRef(time.Date(2018, 12, 1, 9, 15, 30, 0, time.UTC)),
													Kind: "package",
												},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/amzn.json",
			provider: "amazon",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "ALAS-2018-1106",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "ALAS-2018-1106",
							References: []db.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html",
								},
							},
							Aliases: []string{"CVE-2018-14648"},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &db.Package{
								Name:      "389-ds-base",
								Ecosystem: "rpm",
							},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &db.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &db.Package{
								Name:      "389-ds-base-debuginfo",
								Ecosystem: "rpm",
							},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &db.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &db.Package{
								Name:      "389-ds-base-devel",
								Ecosystem: "rpm",
							},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &db.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &db.Package{
								Name:      "389-ds-base-libs",
								Ecosystem: "rpm",
							},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &db.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &db.Package{
								Name:      "389-ds-base-snmp",
								Ecosystem: "rpm",
							},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &db.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/amazon-multiple-kernel-advisories.json",
			provider: "amazon",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "ALAS-2021-1704",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "ALAS-2021-1704",

							References: []db.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2021-1704.html",
								},
							},
							Aliases: []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &db.Fix{Version: "4.14.246-187.474.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &db.Fix{Version: "4.14.246-187.474.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.4-2022-007",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "ALASKERNEL-5.4-2022-007",
							References: []db.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2022-007.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &db.Fix{Version: "5.4.144-69.257.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &db.Fix{Version: "5.4.144-69.257.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.10-2022-005",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "ALASKERNEL-5.10-2022-005",
							References: []db.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-005.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &db.Fix{Version: "5.10.62-55.141.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &db.Fix{Version: "5.10.62-55.141.amzn2", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/azure-linux-3.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2023-29403",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2023-29403",
							Description: "CVE-2023-29403 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []db.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29403",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: azure3OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 0:1.20.7-1.azl3"},
										Fix:     &db.Fix{Version: "0:1.20.7-1.azl3", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/debian-8.json",
			provider: "debian",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2008-7220",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "CVE-2008-7220",
							References: []db.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-7220",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "asterisk"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: "< 1:1.6.2.0~rc3-1"},
										Fix:     &db.Fix{Version: "1:1.6.2.0~rc3-1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "auth2db"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: "< 0.2.5-2+dfsg-1"},
										Fix:     &db.Fix{Version: "0.2.5-2+dfsg-1", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "exaile"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: "< 0.2.14+debian-2.2"},
										Fix:     &db.Fix{Version: "0.2.14+debian-2.2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "wordpress"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: ""},
										Fix:     &db.Fix{Version: "", State: db.NotFixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/debian-8-multiple-entries-for-same-package.json",
			provider: "debian",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2011-4623",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "CVE-2011-4623",
							References: []db.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2011-4623",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: "< 5.7.4-1"},
										Fix:     &db.Fix{Version: "5.7.4-1", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2008-5618",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID: "CVE-2008-5618",
							References: []db.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-5618",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &db.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &db.PackageBlob{
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "dpkg", Constraint: "< 3.18.6-1"},
										Fix:     &db.Fix{Version: "3.18.6-1", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/mariner-20.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2021-37621",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2021-37621",
							Description: "CVE-2021-37621 affecting package exiv2 for versions less than 0.27.5-1. An upgraded version of the package is available that resolves this issue.",
							References: []db.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-37621",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "exiv2"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 0:0.27.5-1.cm2"},
										Fix:     &db.Fix{Version: "0:0.27.5-1.cm2", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},

		{
			name:     "test-fixtures/mariner-range.json",
			provider: "mariner",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2023-29404",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2023-29404",
							Description: "CVE-2023-29404 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []db.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29404",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "> 0:1.19.0.cm2, < 0:1.20.7-1.cm2"},
										Fix:     &db.Fix{Version: "0:1.20.7-1.cm2", State: db.FixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/ol-8.json",
			provider: "oracle",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:          "ELSA-2020-2550",
						ProviderID:    "oracle",
						Provider:      expectedProvider("oracle"),
						Status:        "active",
						PublishedDate: timeRef(time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)),
						BlobValue: &db.VulnerabilityBlob{
							ID:      "ELSA-2020-2550",
							Aliases: []string{"CVE-2020-13112"},
							References: []db.Reference{
								{
									URL: "http://linux.oracle.com/errata/ELSA-2020-2550.html",
								},
								{
									URL: "http://linux.oracle.com/cve/CVE-2020-13112.html",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "libexif"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &db.Fix{Version: "0:0.6.21-17.el8_2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "libexif-devel"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &db.Fix{Version: "0:0.6.21-17.el8_2", State: db.FixedStatus},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "libexif-dummy"},
							BlobValue: &db.PackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{Type: "rpm", Constraint: ""},
										Fix:     &db.Fix{State: db.NotFixedStatus},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/ol-8-modules.json",
			provider: "oracle",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "oracle",
						Provider:   expectedProvider("oracle"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []db.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &db.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   db.FixedStatus,
										},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &db.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   db.FixedStatus,
										},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &db.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   db.FixedStatus,
										},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/rhel-8.json",
			provider: "redhat",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2020-6819",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2020-6819",
							Description: "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
							References: []db.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-6819",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
								{
									Scheme: db.SeveritySchemeCVSS,
									Value: db.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "firefox"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:68.6.1-1.el8_1",
										},
										Fix: &db.Fix{
											Version: "0:68.6.1-1.el8_1",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												Available: &db.FixAvailability{
													Date: timeRef(time.Date(2020, 4, 8, 14, 30, 15, 0, time.UTC)),
													Kind: "advisory",
												},
												References: []db.Reference{
													{
														ID:   "RHSA-2020:1341",
														URL:  "https://access.redhat.com/errata/RHSA-2020:1341",
														Tags: []string{db.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "thunderbird"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{RpmModularity: strRef("")},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:68.7.0-1.el8_1",
										},
										Fix: &db.Fix{
											Version: "0:68.7.0-1.el8_1",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												References: []db.Reference{
													{
														ID:   "RHSA-2020:1495",
														URL:  "https://access.redhat.com/errata/RHSA-2020:1495",
														Tags: []string{db.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
		{
			name:     "test-fixtures/rhel-8-modules.json",
			provider: "redhat",
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &db.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &db.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []db.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []db.Severity{
								{
									Scheme: db.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
								{
									Scheme: db.SeveritySchemeCVSS,
									Value: db.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						db.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &db.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												References: []db.Reference{
													{
														ID:   "RHSA-2020:3669",
														URL:  "https://access.redhat.com/errata/RHSA-2020:3669",
														Tags: []string{db.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &db.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												References: []db.Reference{
													{
														ID:   "RHSA-2020:5620",
														URL:  "https://access.redhat.com/errata/RHSA-2020:5620",
														Tags: []string{db.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						db.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &db.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &db.PackageBlob{
								Qualifiers: &db.PackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []db.Range{
									{
										Version: db.Version{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &db.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   db.FixedStatus,
											Detail: &db.FixDetail{
												References: []db.Reference{
													{
														ID:   "RHSA-2020:5619",
														URL:  "https://access.redhat.com/errata/RHSA-2020:5619",
														Tags: []string{db.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vulns := loadFixture(t, test.name)

			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState(test.provider))
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

func TestGetOperatingSystem(t *testing.T) {
	tests := []struct {
		name      string
		osName    string
		osID      string
		osVersion string
		channel   string
		expected  *db.OperatingSystem
	}{
		{
			name:      "works with given args",
			osName:    "alpine",
			osID:      "alpine",
			osVersion: "3.10",
			expected: &db.OperatingSystem{
				Name:         "alpine",
				ReleaseID:    "alpine",
				MajorVersion: "3",
				MinorVersion: "10",
				LabelVersion: "",
				Codename:     "",
			},
		},
		{
			name:      "does codename lookup (debian)",
			osName:    "debian",
			osID:      "debian",
			osVersion: "11",
			expected: &db.OperatingSystem{
				Name:         "debian",
				ReleaseID:    "debian",
				MajorVersion: "11",
				MinorVersion: "",
				LabelVersion: "",
				Codename:     "bullseye",
			},
		},
		{
			name:      "does codename lookup (ubuntu)",
			osName:    "ubuntu",
			osID:      "ubuntu",
			osVersion: "22.04",
			expected: &db.OperatingSystem{
				Name:         "ubuntu",
				ReleaseID:    "ubuntu",
				MajorVersion: "22",
				MinorVersion: "04",
				LabelVersion: "",
				Codename:     "jammy",
			},
		},
		{
			name:      "includes channel (rhel)",
			osName:    "redhat",
			osID:      "rhel",
			osVersion: "8.4",
			channel:   "eus",
			expected: &db.OperatingSystem{
				Name:         "redhat",
				ReleaseID:    "rhel",
				MajorVersion: "8",
				MinorVersion: "4",
				Channel:      "eus",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOperatingSystem(tt.osName, tt.osID, tt.osVersion, tt.channel)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestGetOSInfo(t *testing.T) {
	tests := []struct {
		name     string
		group    string
		expected osInfo
	}{
		{
			name:  "alpine 3.10",
			group: "alpine:3.10",
			expected: osInfo{
				name:    "alpine",
				id:      "alpine",
				version: "3.10",
			},
		},
		{
			name:  "debian bullseye",
			group: "debian:11",
			expected: osInfo{
				name:    "debian",
				id:      "debian",
				version: "11",
			},
		},
		{
			name:  "mariner version 1",
			group: "mariner:1.0",
			expected: osInfo{
				name:    "mariner",
				id:      "mariner",
				version: "1.0",
			},
		},
		{
			name:  "mariner version 3 (azurelinux conversion)",
			group: "mariner:3.0",
			expected: osInfo{
				name:    "azurelinux",
				id:      "azurelinux",
				version: "3.0",
			},
		},
		{
			name:  "ubuntu focal",
			group: "ubuntu:20.04",
			expected: osInfo{
				name:    "ubuntu",
				id:      "ubuntu",
				version: "20.04",
			},
		},
		{
			name:  "oracle linux",
			group: "ol:8",
			expected: osInfo{
				name:    "oraclelinux", // normalize name
				id:      "ol",          // keep original ID
				version: "8",
			},
		},
		{
			name:  "redhat 8",
			group: "rhel:8",
			expected: osInfo{
				name:    "redhat",
				id:      "rhel",
				version: "8",
			},
		},
		{
			name:  "rhel + eus",
			group: "rhel:8+eus",
			expected: osInfo{
				name:    "redhat",
				id:      "rhel",
				version: "8",
				channel: "eus",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oi := getOSInfo(tt.group)
			assert.Equal(t, tt.expected, oi, "expected osInfo to match for group %s", tt.group)
		})
	}
}

func TestGetFixAvailability(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected map[string]*db.FixAvailability // keyed by package name for fixture-based testing
	}{
		{
			name:    "alpine-3.9 with package availability",
			fixture: "test-fixtures/alpine-3.9.json",
			expected: map[string]*db.FixAvailability{
				"xen": {
					Date: timeRef(time.Date(2018, 12, 1, 9, 15, 30, 0, time.UTC)),
					Kind: "package",
				},
			},
		},
		{
			name:    "rhel-8 with advisory availability",
			fixture: "test-fixtures/rhel-8.json",
			expected: map[string]*db.FixAvailability{
				"firefox": {
					Date: timeRef(time.Date(2020, 4, 8, 14, 30, 15, 0, time.UTC)),
					Kind: "advisory",
				},
				"thunderbird": nil, // no availability data in fixture
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerabilities := loadFixture(t, tt.fixture)
			require.Len(t, vulnerabilities, 1, "expected exactly one vulnerability")

			for _, fixedIn := range vulnerabilities[0].Vulnerability.FixedIn {
				result := getFixAvailability(fixedIn)
				expected := tt.expected[fixedIn.Name]

				if expected == nil {
					require.Nil(t, result, "expected nil availability for %s", fixedIn.Name)
				} else {
					require.NotNil(t, result, "expected non-nil availability for %s", fixedIn.Name)
					require.Equal(t, expected.Kind, result.Kind)
					require.Equal(t, expected.Date, result.Date)
				}
			}
		})
	}

	// keep edge case test for scenarios not covered by fixtures
	t.Run("invalid date returns nil", func(t *testing.T) {
		fixedIn := unmarshal.OSFixedIn{
			Available: struct {
				Date string `json:"Date,omitempty"`
				Kind string `json:"Kind,omitempty"`
			}{
				Date: "invalid-date",
				Kind: "commit",
			},
		}
		result := getFixAvailability(fixedIn)
		require.Nil(t, result)
	})
}

func TestGetFixWithDetail(t *testing.T) {
	tests := []struct {
		name     string
		fixedIn  unmarshal.OSFixedIn
		expected *db.Fix
	}{
		{
			name: "fix with version and availability",
			fixedIn: unmarshal.OSFixedIn{
				Version: "1.2.3",
				Available: struct {
					Date string `json:"Date,omitempty"`
					Kind string `json:"Kind,omitempty"`
				}{
					Date: "2023-01-15T10:30:45Z",
					Kind: "advisory",
				},
				VendorAdvisory: struct {
					AdvisorySummary []struct {
						ID   string `json:"ID"`
						Link string `json:"Link"`
					} `json:"AdvisorySummary"`
					NoAdvisory bool `json:"NoAdvisory"`
				}{
					AdvisorySummary: []struct {
						ID   string `json:"ID"`
						Link string `json:"Link"`
					}{
						{
							ID:   "RHSA-2023-001",
							Link: "https://access.redhat.com/errata/RHSA-2023-001",
						},
					},
				},
			},
			expected: &db.Fix{
				Version: "1.2.3",
				State:   db.FixedStatus,
				Detail: &db.FixDetail{
					Available: &db.FixAvailability{
						Date: timeRef(time.Date(2023, 1, 15, 10, 30, 45, 0, time.UTC)),
						Kind: "advisory",
					},
					References: []db.Reference{
						{
							ID:   "RHSA-2023-001",
							URL:  "https://access.redhat.com/errata/RHSA-2023-001",
							Tags: []string{db.AdvisoryReferenceTag},
						},
					},
				},
			},
		},
		{
			name: "fix with version but no availability or references",
			fixedIn: unmarshal.OSFixedIn{
				Version: "2.0.0",
				Available: struct {
					Date string `json:"Date,omitempty"`
					Kind string `json:"Kind,omitempty"`
				}{},
			},
			expected: &db.Fix{
				Version: "2.0.0",
				State:   db.FixedStatus,
				Detail:  nil,
			},
		},
		{
			name: "no fix version with availability",
			fixedIn: unmarshal.OSFixedIn{
				Version: "",
				Available: struct {
					Date string `json:"Date,omitempty"`
					Kind string `json:"Kind,omitempty"`
				}{
					Date: "2023-01-15T10:30:45Z",
					Kind: "release",
				},
			},
			expected: &db.Fix{
				Version: "",
				State:   db.NotFixedStatus,
				Detail: &db.FixDetail{
					Available: &db.FixAvailability{
						Date: timeRef(time.Date(2023, 1, 15, 10, 30, 45, 0, time.UTC)),
						Kind: "release",
					},
				},
			},
		},
		{
			name: "vendor advisory with no advisory flag set",
			fixedIn: unmarshal.OSFixedIn{
				Version: "",
				Available: struct {
					Date string `json:"Date,omitempty"`
					Kind string `json:"Kind,omitempty"`
				}{},
				VendorAdvisory: struct {
					AdvisorySummary []struct {
						ID   string `json:"ID"`
						Link string `json:"Link"`
					} `json:"AdvisorySummary"`
					NoAdvisory bool `json:"NoAdvisory"`
				}{
					NoAdvisory: true,
				},
			},
			expected: &db.Fix{
				Version: "",
				State:   db.WontFixStatus,
				Detail:  nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFix(tt.fixedIn)

			if d := cmp.Diff(tt.expected, result); d != "" {
				t.Fatalf("unexpected result: %s", d)
			}
		})
	}
}

func TestGetFixWithDetailFixtures(t *testing.T) {
	// additional fixture-based tests to complement the existing ad-hoc tests
	tests := []struct {
		name     string
		fixture  string
		expected map[string]*db.Fix // keyed by package name
	}{
		{
			name:    "alpine-3.9 with availability",
			fixture: "test-fixtures/alpine-3.9.json",
			expected: map[string]*db.Fix{
				"xen": {
					Version: "4.11.1-r0",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: timeRef(time.Date(2018, 12, 1, 9, 15, 30, 0, time.UTC)),
							Kind: "package",
						},
					},
				},
			},
		},
		{
			name:    "rhel-8 with availability and advisory references",
			fixture: "test-fixtures/rhel-8.json",
			expected: map[string]*db.Fix{
				"firefox": {
					Version: "0:68.6.1-1.el8_1",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						Available: &db.FixAvailability{
							Date: timeRef(time.Date(2020, 4, 8, 14, 30, 15, 0, time.UTC)),
							Kind: "advisory",
						},
						References: []db.Reference{
							{
								ID:   "RHSA-2020:1341",
								URL:  "https://access.redhat.com/errata/RHSA-2020:1341",
								Tags: []string{db.AdvisoryReferenceTag},
							},
						},
					},
				},
				"thunderbird": {
					Version: "0:68.7.0-1.el8_1",
					State:   db.FixedStatus,
					Detail: &db.FixDetail{
						References: []db.Reference{
							{
								ID:   "RHSA-2020:1495",
								URL:  "https://access.redhat.com/errata/RHSA-2020:1495",
								Tags: []string{db.AdvisoryReferenceTag},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerabilities := loadFixture(t, tt.fixture)
			require.Len(t, vulnerabilities, 1, "expected exactly one vulnerability")

			for _, fixedIn := range vulnerabilities[0].Vulnerability.FixedIn {
				result := getFix(fixedIn)
				expected := tt.expected[fixedIn.Name]

				require.NotNil(t, expected, "no expected result for package %s", fixedIn.Name)
				if d := cmp.Diff(expected, result); d != "" {
					t.Fatalf("unexpected result for %s: %s", fixedIn.Name, d)
				}
			}
		})
	}
}

func affectedPkgSlice(a ...db.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer testutil.CloseFile(f)

	entries, err := unmarshal.OSVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func timeRef(ti time.Time) *time.Time {
	return &ti
}

func strRef(s string) *string {
	return &s
}
