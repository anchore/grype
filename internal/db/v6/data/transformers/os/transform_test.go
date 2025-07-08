package os

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
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

func inputProviderState(name string) provider.State {
	return provider.State{
		Provider:  name,
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider(name string) *v6.Provider {
	return &v6.Provider{
		ID:           name,
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func TestTransform(t *testing.T) {

	alpineOS := &v6.OperatingSystem{
		Name:         "alpine",
		ReleaseID:    "alpine",
		MajorVersion: "3",
		MinorVersion: "9",
	}

	amazonOS := &v6.OperatingSystem{
		Name:         "amazonlinux",
		ReleaseID:    "amzn",
		MajorVersion: "2",
	}
	azure3OS := &v6.OperatingSystem{
		Name:         "azurelinux",
		ReleaseID:    "azurelinux",
		MajorVersion: "3",
		MinorVersion: "0", // TODO: is this right?
	}
	debian8OS := &v6.OperatingSystem{
		Name:         "debian",
		ReleaseID:    "debian",
		MajorVersion: "8",
		Codename:     "jessie",
	}

	mariner2OS := &v6.OperatingSystem{
		Name:         "mariner",
		ReleaseID:    "mariner",
		MajorVersion: "2",
		MinorVersion: "0", // TODO: is this right?
	}
	ol8OS := &v6.OperatingSystem{
		Name:         "oraclelinux",
		ReleaseID:    "ol",
		MajorVersion: "8",
	}
	rhel8OS := &v6.OperatingSystem{
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2018-19967",
						Status:     "active",
						ProviderID: "alpine",
						Provider:   expectedProvider("alpine"),
						BlobValue: &v6.VulnerabilityBlob{
							ID: "CVE-2018-19967",
							References: []v6.Reference{
								{
									URL: "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: alpineOS,
							Package:         &v6.Package{Ecosystem: "apk", Name: "xen"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "apk", Constraint: "< 4.11.1-r0"},
										Fix:     &v6.Fix{Version: "4.11.1-r0", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "ALAS-2018-1106",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "ALAS-2018-1106",
							References: []v6.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html",
								},
							},
							Aliases: []string{"CVE-2018-14648"},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &v6.Package{
								Name:      "389-ds-base",
								Ecosystem: "rpm",
							},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &v6.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &v6.Package{
								Name:      "389-ds-base-debuginfo",
								Ecosystem: "rpm",
							},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &v6.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &v6.Package{
								Name:      "389-ds-base-devel",
								Ecosystem: "rpm",
							},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &v6.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &v6.Package{
								Name:      "389-ds-base-libs",
								Ecosystem: "rpm",
							},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &v6.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package: &v6.Package{
								Name:      "389-ds-base-snmp",
								Ecosystem: "rpm",
							},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2018-14648"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 1.3.8.4-15.amzn2.0.1"},
										Fix:     &v6.Fix{Version: "1.3.8.4-15.amzn2.0.1", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "ALAS-2021-1704",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "ALAS-2021-1704",

							References: []v6.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALAS-2021-1704.html",
								},
							},
							Aliases: []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &v6.Fix{Version: "4.14.246-187.474.amzn2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3732"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 4.14.246-187.474.amzn2"},
										Fix:     &v6.Fix{Version: "4.14.246-187.474.amzn2", State: v6.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.4-2022-007",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "ALASKERNEL-5.4-2022-007",
							References: []v6.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2022-007.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &v6.Fix{Version: "5.4.144-69.257.amzn2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: ">= 5.4, < 5.4.144-69.257.amzn2"},
										Fix:     &v6.Fix{Version: "5.4.144-69.257.amzn2", State: v6.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "ALASKERNEL-5.10-2022-005",
						ProviderID: "amazon",
						Provider:   expectedProvider("amazon"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "ALASKERNEL-5.10-2022-005",
							References: []v6.Reference{
								{
									URL: "https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-005.html",
								},
							},
							Aliases: []string{"CVE-2021-3753", "CVE-2021-40490"},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &v6.Fix{Version: "5.10.62-55.141.amzn2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: amazonOS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "kernel-headers"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2021-3753", "CVE-2021-40490"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: ">= 5.10, < 5.10.62-55.141.amzn2"},
										Fix:     &v6.Fix{Version: "5.10.62-55.141.amzn2", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2023-29403",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2023-29403",
							Description: "CVE-2023-29403 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []v6.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29403",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: azure3OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 0:1.20.7-1.azl3"},
										Fix:     &v6.Fix{Version: "0:1.20.7-1.azl3", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2008-7220",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "CVE-2008-7220",
							References: []v6.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-7220",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "high",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "asterisk"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: "< 1:1.6.2.0~rc3-1"},
										Fix:     &v6.Fix{Version: "1:1.6.2.0~rc3-1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "auth2db"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: "< 0.2.5-2+dfsg-1"},
										Fix:     &v6.Fix{Version: "0.2.5-2+dfsg-1", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "exaile"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: "< 0.2.14+debian-2.2"},
										Fix:     &v6.Fix{Version: "0.2.14+debian-2.2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "wordpress"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: ""},
										Fix:     &v6.Fix{Version: "", State: v6.NotFixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2011-4623",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "CVE-2011-4623",
							References: []v6.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2011-4623",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: "< 5.7.4-1"},
										Fix:     &v6.Fix{Version: "5.7.4-1", State: v6.FixedStatus},
									},
								},
							},
						},
					),
				},
				{
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2008-5618",
						ProviderID: "debian",
						Provider:   expectedProvider("debian"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID: "CVE-2008-5618",
							References: []v6.Reference{
								{
									URL: "https://security-tracker.debian.org/tracker/CVE-2008-5618",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "low",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: debian8OS,
							Package:         &v6.Package{Ecosystem: "deb", Name: "rsyslog"},
							BlobValue: &v6.AffectedPackageBlob{
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "dpkg", Constraint: "< 3.18.6-1"},
										Fix:     &v6.Fix{Version: "3.18.6-1", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2021-37621",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2021-37621",
							Description: "CVE-2021-37621 affecting package exiv2 for versions less than 0.27.5-1. An upgraded version of the package is available that resolves this issue.",
							References: []v6.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-37621",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "exiv2"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 0:0.27.5-1.cm2"},
										Fix:     &v6.Fix{Version: "0:0.27.5-1.cm2", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2023-29404",
						ProviderID: "mariner",
						Provider:   expectedProvider("mariner"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2023-29404",
							Description: "CVE-2023-29404 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
							References: []v6.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29404",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: mariner2OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "golang"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "> 0:1.19.0.cm2, < 0:1.20.7-1.cm2"},
										Fix:     &v6.Fix{Version: "0:1.20.7-1.cm2", State: v6.FixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:          "ELSA-2020-2550",
						ProviderID:    "oracle",
						Provider:      expectedProvider("oracle"),
						Status:        "active",
						PublishedDate: timeRef(time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)),
						BlobValue: &v6.VulnerabilityBlob{
							ID:      "ELSA-2020-2550",
							Aliases: []string{"CVE-2020-13112"},
							References: []v6.Reference{
								{
									URL: "http://linux.oracle.com/errata/ELSA-2020-2550.html",
								},
								{
									URL: "http://linux.oracle.com/cve/CVE-2020-13112.html",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "libexif"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &v6.Fix{Version: "0:0.6.21-17.el8_2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "libexif-devel"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: "< 0:0.6.21-17.el8_2"},
										Fix:     &v6.Fix{Version: "0:0.6.21-17.el8_2", State: v6.FixedStatus},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "libexif-dummy"},
							BlobValue: &v6.AffectedPackageBlob{
								CVEs:       []string{"CVE-2020-13112"},
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{Type: "rpm", Constraint: ""},
										Fix:     &v6.Fix{State: v6.NotFixedStatus},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "oracle",
						Provider:   expectedProvider("oracle"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []v6.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
							},
						},
					},

					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &v6.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   v6.FixedStatus,
										},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &v6.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   v6.FixedStatus,
										},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: ol8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &v6.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   v6.FixedStatus,
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2020-6819",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2020-6819",
							Description: "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
							References: []v6.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-6819",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "critical",
									Rank:   1,
								},
								{
									Scheme: v6.SeveritySchemeCVSS,
									Value: v6.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "firefox"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:68.6.1-1.el8_1",
										},
										Fix: &v6.Fix{
											Version: "0:68.6.1-1.el8_1",
											State:   v6.FixedStatus,
											Detail: &v6.FixDetail{
												References: []v6.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:1341",
														Tags: []string{v6.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "thunderbird"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{RpmModularity: strRef("")},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:68.7.0-1.el8_1",
										},
										Fix: &v6.Fix{
											Version: "0:68.7.0-1.el8_1",
											State:   v6.FixedStatus,
											Detail: &v6.FixDetail{
												References: []v6.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:1495",
														Tags: []string{v6.AdvisoryReferenceTag},
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
					VulnerabilityHandle: &v6.VulnerabilityHandle{
						Name:       "CVE-2020-14350",
						ProviderID: "redhat",
						Provider:   expectedProvider("redhat"),
						Status:     "active",
						BlobValue: &v6.VulnerabilityBlob{
							ID:          "CVE-2020-14350",
							Description: "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
							References: []v6.Reference{
								{
									URL: "https://access.redhat.com/security/cve/CVE-2020-14350",
								},
							},
							Severities: []v6.Severity{
								{
									Scheme: v6.SeveritySchemeCHMLN,
									Value:  "medium",
									Rank:   1,
								},
								{
									Scheme: v6.SeveritySchemeCVSS,
									Value: v6.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Rank: 2,
								},
							},
						},
					},
					Related: affectedPkgSlice(
						v6.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:10"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
										},
										Fix: &v6.Fix{
											Version: "0:10.14-1.module+el8.2.0+7801+be0fed80",
											State:   v6.FixedStatus,
											Detail: &v6.FixDetail{
												References: []v6.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:3669",
														Tags: []string{v6.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:12"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
										},
										Fix: &v6.Fix{
											Version: "0:12.5-1.module+el8.3.0+9042+664538f4",
											State:   v6.FixedStatus,
											Detail: &v6.FixDetail{
												References: []v6.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:5620",
														Tags: []string{v6.AdvisoryReferenceTag},
													},
												},
											},
										},
									},
								},
							},
						},
						v6.AffectedPackageHandle{
							OperatingSystem: rhel8OS,
							Package:         &v6.Package{Ecosystem: "rpm", Name: "postgresql"},
							BlobValue: &v6.AffectedPackageBlob{
								Qualifiers: &v6.AffectedPackageQualifiers{
									RpmModularity: strRef("postgresql:9.6"),
								},
								Ranges: []v6.AffectedRange{
									{
										Version: v6.AffectedVersion{
											Type:       "rpm",
											Constraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
										},
										Fix: &v6.Fix{
											Version: "0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
											State:   v6.FixedStatus,
											Detail: &v6.FixDetail{
												References: []v6.Reference{
													{
														URL:  "https://access.redhat.com/errata/RHSA-2020:5619",
														Tags: []string{v6.AdvisoryReferenceTag},
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
		expected  *v6.OperatingSystem
	}{
		{
			name:      "works with given args",
			osName:    "alpine",
			osID:      "alpine",
			osVersion: "3.10",
			expected: &v6.OperatingSystem{
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
			expected: &v6.OperatingSystem{
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
			expected: &v6.OperatingSystem{
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
			expected: &v6.OperatingSystem{
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
		name            string
		group           string
		expectedOS      string
		expectedID      string
		expectedVersion string
		expectedChannel string
	}{
		{
			name:            "alpine 3.10",
			group:           "alpine:3.10",
			expectedOS:      "alpine",
			expectedID:      "alpine",
			expectedVersion: "3.10",
		},
		{
			name:            "debian bullseye",
			group:           "debian:11",
			expectedOS:      "debian",
			expectedID:      "debian",
			expectedVersion: "11",
		},
		{
			name:            "mariner version 1",
			group:           "mariner:1.0",
			expectedOS:      "mariner",
			expectedID:      "mariner",
			expectedVersion: "1.0",
		},
		{
			name:            "mariner version 3 (azurelinux conversion)",
			group:           "mariner:3.0",
			expectedOS:      "azurelinux",
			expectedID:      "azurelinux",
			expectedVersion: "3.0",
		},
		{
			name:            "ubuntu focal",
			group:           "ubuntu:20.04",
			expectedOS:      "ubuntu",
			expectedID:      "ubuntu",
			expectedVersion: "20.04",
		},
		{
			name:            "oracle linux",
			group:           "ol:8",
			expectedOS:      "oraclelinux", // normalize name
			expectedID:      "ol",          // keep original ID
			expectedVersion: "8",
		},
		{
			name:            "redhat 8",
			group:           "rhel:8",
			expectedOS:      "redhat",
			expectedID:      "rhel",
			expectedVersion: "8",
		},
		{
			name:            "rhel + eus",
			group:           "rhel:8+eus",
			expectedOS:      "redhat",
			expectedID:      "rhel",
			expectedVersion: "8",
			expectedChannel: "eus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osName, id, version, channel := getOSInfo(tt.group)
			assert.Equal(t, tt.expectedOS, osName)
			assert.Equal(t, tt.expectedID, id)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedChannel, channel)
		})
	}
}

func affectedPkgSlice(a ...v6.AffectedPackageHandle) []any {
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
	defer func() {
		require.NoError(t, f.Close())
	}()

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
