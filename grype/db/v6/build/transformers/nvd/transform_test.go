package nvd

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider/unmarshal/nvd"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/tests"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

var (
	timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	listing = provider.File{
		Path:      "some",
		Digest:    "123456",
		Algorithm: "sha256",
	}
)

func inputProviderState(name string) provider.State {
	return provider.State{
		Provider:  name,
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider(name string) *grypeDB.Provider {
	return &grypeDB.Provider{
		ID:           name,
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func TestTransform(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		config   Config
		provider string
		want     []transformers.RelatedEntries
	}{
		{
			name:     "basic version range",
			fixture:  "test-fixtures/version-range.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-5487",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2018, 7, 5, 13, 52, 30, 627000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 5, 24, 14, 29, 0, 390000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-5487",
							Assigners:   []string{"security-alert@netapp.com"},
							Description: "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20180523-0001/",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
										Version: "4.0",
									},
									Source: "security@zabbix.com",
									Rank:   2,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-5487"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 7.2, <= 7.3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "netapp",
								Product: "oncommand_unified_manager",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-5487",
							CWE:    "CWE-20",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "with fix version information",
			fixture:  "test-fixtures/fix-version.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-5487",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2018, 7, 5, 13, 52, 30, 627000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 5, 24, 14, 29, 0, 390000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-5487",
							Assigners:   []string{"security-alert@netapp.com"},
							Description: "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20180523-0001/",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
										Version: "4.0",
									},
									Source: "security@zabbix.com",
									Rank:   2,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-5487"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 7.2, < 7.3",
										},
										Fix: &grypeDB.Fix{
											Version: "7.3",
											State:   grypeDB.FixedStatus,
											Detail: &grypeDB.FixDetail{ // important! fix detail is associated to the record
												Available: &grypeDB.FixAvailability{
													Date: timeRef(time.Date(2018, 5, 23, 0, 0, 0, 0, time.UTC)),
													Kind: "advisory",
												},
											},
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "netapp",
								Product: "oncommand_unified_manager",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-5487",
							CWE:    "CWE-20",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "mismatched fix info",
			fixture:  "test-fixtures/fix-wrong-version.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-5487",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2018, 7, 5, 13, 52, 30, 627000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 5, 24, 14, 29, 0, 390000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-5487",
							Assigners:   []string{"security-alert@netapp.com"},
							Description: "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20180523-0001/",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
										Version: "4.0",
									},
									Source: "security@zabbix.com",
									Rank:   2,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-5487"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 7.2, < 7.3",
										},
										Fix: &grypeDB.Fix{
											Version: "7.3",
											State:   grypeDB.FixedStatus,
											Detail:  nil, // important! though there is fix info on the record, the versions mismatch, thus the detail is not attached (there is a bug upstream)
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "netapp",
								Product: "oncommand_unified_manager",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-5487",
							CWE:    "CWE-20",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "single package, multiple distros",
			fixture:  "test-fixtures/single-package-multi-distro.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-1000222",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2020, 3, 31, 2, 15, 12, 667000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 8, 20, 20, 29, 1, 347000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-1000222",
							Assigners:   []string{"cve@mitre.org"},
							Description: "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-1000222",
								},
								{
									URL:  "https://github.com/libgd/libgd/issues/447",
									Tags: []string{"issue-tracking", "third-party-advisory"},
								},
								{
									URL:  "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL: "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/",
								},
								{
									URL:  "https://security.gentoo.org/glsa/201903-18",
									Tags: []string{"third-party-advisory"},
								},
								{
									URL:  "https://usn.ubuntu.com/3755-1/",
									Tags: []string{"mitigation", "third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						// the application package...
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-1000222"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 2.2.5",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "libgd",
								Product: "libgd",
							},
						},
						// ubuntu OS ... (since the default config has all parts enabled, we should see this)
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-1000222"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 14.04",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 16.04",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 18.04",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:            "o",
								Vendor:          "canonical",
								Product:         "ubuntu_linux",
								SoftwareEdition: "lts",
							},
						},
						// debian OS ...  (since the default config has all parts enabled, we should see this)
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-1000222"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 8.0",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "o",
								Vendor:  "debian",
								Product: "debian_linux",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-1000222",
							CWE:    "CWE-415",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "single package, multiple distros (application types only)",
			fixture:  "test-fixtures/single-package-multi-distro.json",
			provider: "nvd",
			config: func() Config {
				c := defaultConfig()
				c.CPEParts.Remove("h", "o") // important!
				return c
			}(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-1000222",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2020, 3, 31, 2, 15, 12, 667000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 8, 20, 20, 29, 1, 347000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-1000222",
							Assigners:   []string{"cve@mitre.org"},
							Description: "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-1000222",
								},
								{
									URL:  "https://github.com/libgd/libgd/issues/447",
									Tags: []string{"issue-tracking", "third-party-advisory"},
								},
								{
									URL:  "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL: "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/",
								},
								{
									URL:  "https://security.gentoo.org/glsa/201903-18",
									Tags: []string{"third-party-advisory"},
								},
								{
									URL:  "https://usn.ubuntu.com/3755-1/",
									Tags: []string{"mitigation", "third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-1000222"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 2.2.5",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "libgd",
								Product: "libgd",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-1000222",
							CWE:    "CWE-415",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "multiple packages, multiple distros",
			fixture:  "test-fixtures/compound-pkg.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2018-10189",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2018, 5, 23, 14, 41, 49, 73000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2018, 4, 17, 20, 29, 0, 410000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2018-10189",
							Assigners:   []string{"cve@mitre.org"},
							Description: "An issue was discovered in Mautic 1.x and 2.x before 2.13.0. It is possible to systematically emulate tracking cookies per contact due to tracking the contact by their auto-incremented ID. Thus, a third party can manipulate the cookie value with +1 to systematically assume being tracked as each contact in Mautic. It is then possible to retrieve information about the contact through forms that have progressive profiling enabled.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-10189",
								},
								{
									URL:  "https://github.com/mautic/mautic/releases/tag/2.13.0",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:P/I:N/A:N",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2018-10189"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 1.0.0, <= 1.4.1",
										},
										// since the top range operator is <= we cannot infer a fix
									},
									{
										Version: grypeDB.Version{
											Constraint: ">= 2.0.0, < 2.13.0",
										},
										Fix: &grypeDB.Fix{
											Version: "2.13.0",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "mautic",
								Product: "mautic",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2018-10189",
							CWE:    "CWE-200",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "invalid CPE",
			fixture:  "test-fixtures/invalid_cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2015-8978",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2016, 11, 28, 19, 50, 59, 600000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2016, 11, 22, 17, 59, 0, 180000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2015-8978",
							Assigners:   []string{"cve@mitre.org"},
							Description: "In Soap Lite (aka the SOAP::Lite extension for Perl) 1.14 and earlier, an example attack consists of defining 10 or more XML entities, each defined as consisting of 10 of the previous entity, with the document consisting of a single instance of the largest entity, which expands to one billion copies of the first entity. The amount of computer memory used for handling an external SOAP call would likely exceed that available to the process parsing the XML.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2015-8978",
								},
								{
									URL:  "http://cpansearch.perl.org/src/PHRED/SOAP-Lite-1.20/Changes",
									Tags: []string{"vendor-advisory"},
								},
								{
									URL:  "http://www.securityfocus.com/bid/94487",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										Version: "3.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:N/I:N/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.CWEHandle{
							CVE:    "CVE-2015-8978",
							CWE:    "CWE-399",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					), // when we can't parse the CPE we should not add any affected CPE blobs (but we do add the vuln blob and CWE)
				},
			},
		},
		{
			name:     "basic platform CPE",
			fixture:  "test-fixtures/platform-cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2022-26488",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2022, 9, 3, 3, 34, 19, 933000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2022, 3, 10, 17, 47, 45, 383000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2022-26488",
							Assigners:   []string{"cve@mitre.org"},
							Description: "In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled PATH entries. A non-administrative user can trigger a repair that incorrectly adds user-writable paths into PATH, enabling search-path hijacking of other users and system services. This affects Python (CPython) through 3.7.12, 3.8.x through 3.8.12, 3.9.x through 3.9.10, and 3.10.x through 3.10.2.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2022-26488",
								},
								{
									URL:  "https://mail.python.org/archives/list/security-announce@python.org/thread/657Z4XULWZNIY5FRP3OWXHYKUSIH6DMN/",
									Tags: []string{"patch", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20220419-0005/",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:L/AC:M/Au:N/C:P/I:P/A:P",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2022-26488"},
								Ranges: []grypeDB.Range{
									{
										// match all versions
										Version: grypeDB.Version{Constraint: ""},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:           "a",
								Vendor:         "netapp",
								Product:        "active_iq_unified_manager",
								TargetSoftware: "windows",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2022-26488"},
								Ranges: []grypeDB.Range{
									{
										// match all versions
										Version: grypeDB.Version{Constraint: ""},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "netapp",
								Product: "ontap_select_deploy_administration_utility",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2022-26488"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}, // important!
								},
								Ranges: []grypeDB.Range{
									{Version: grypeDB.Version{Constraint: "<= 3.7.12"}},
									{Version: grypeDB.Version{Constraint: ">= 3.10.0, <= 3.10.2"}},
									{Version: grypeDB.Version{Constraint: ">= 3.8.0, <= 3.8.12"}},
									{Version: grypeDB.Version{Constraint: ">= 3.9.0, <= 3.9.10"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha1"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha2"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha3"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha4"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha5"}},
									{Version: grypeDB.Version{Constraint: "= 3.11.0-alpha6"}},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "python",
								Product: "python",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2022-26488",
							CWE:    "CWE-426",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "multiple platform CPEs for single package",
			fixture:  "test-fixtures/cve-2022-0543.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2022-0543",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2023, 9, 29, 15, 55, 24, 533000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2022, 2, 18, 20, 15, 17, 583000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2022-0543",
							Assigners:   []string{"security@debian.org"},
							Description: "It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
								},
								{
									URL:  "http://packetstormsecurity.com/files/166885/Redis-Lua-Sandbox-Escape.html",
									Tags: []string{"exploit", "third-party-advisory", "vdb-entry"},
								},
								{
									URL:  "https://bugs.debian.org/1005787",
									Tags: []string{"issue-tracking", "patch", "third-party-advisory"},
								},
								{
									URL:  "https://lists.debian.org/debian-security-announce/2022/msg00048.html",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20220331-0004/",
									Tags: []string{"third-party-advisory"},
								},
								{
									URL:  "https://www.debian.org/security/2022/dsa-5081",
									Tags: []string{"mailing-list", "third-party-advisory"},
								},
								{
									URL:  "https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:L/Au:N/C:C/I:C/A:C",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2022-0543"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
										"cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
										"cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
									},
								},
								Ranges: []grypeDB.Range{
									{
										// match all versions
										Version: grypeDB.Version{Constraint: ""},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "redis",
								Product: "redis",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2022-0543",
							CWE:    "CWE-862",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "multiple platform CPEs for single package + fix and OS match",
			fixture:  "test-fixtures/cve-2020-10729.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2020-10729",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2021, 12, 10, 19, 57, 6, 357000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2021, 5, 27, 19, 15, 7, 880000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2020-10729",
							Assigners:   []string{"secalert@redhat.com"},
							Description: "A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-10729",
								},
								{
									URL:  "https://bugzilla.redhat.com/show_bug.cgi?id=1831089",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://github.com/ansible/ansible/issues/34144",
									Tags: []string{"exploit", "issue-tracking", "third-party-advisory"},
								},
								{
									URL:  "https://www.debian.org/security/2021/dsa-4950",
									Tags: []string{"third-party-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:L/AC:L/Au:N/C:P/I:N/A:N",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2020-10729"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*",
										"cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
									},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "< 2.9.6",
										},
										Fix: &grypeDB.Fix{
											Version: "2.9.6",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "redhat",
								Product: "ansible_engine",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2020-10729"},
								// note: no qualifiers !
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 10.0",
										},
										// note: no fix!
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "o",
								Vendor:  "debian",
								Product: "debian_linux",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2020-10729",
							CWE:    "CWE-330",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2020-10729",
							CWE:    "CWE-330",
							Source: "secalert@redhat.com",
							Type:   "Secondary",
						},
					),
				},
			},
		},
		{
			name:     "application type as platform CPE",
			fixture:  "test-fixtures/multiple-platforms-with-application-cpe.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2023-38733",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2023, 8, 26, 2, 25, 42, 957000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2023, 8, 22, 22, 15, 8, 460000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-38733",
							Assigners:   []string{"psirt@us.ibm.com"},
							Description: "IBM Robotic Process Automation 21.0.0 through 21.0.7.1 and 23.0.0 through 23.0.1 server could allow an authenticated user to view sensitive information from installation logs.  IBM X-Force Id:  262293.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-38733",
								},
								{
									URL:  "https://exchange.xforce.ibmcloud.com/vulnerabilities/262293",
									Tags: []string{"vdb-entry", "vendor-advisory"},
								},
								{
									URL:  "https://www.ibm.com/support/pages/node/7028223",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
										Version: "3.1",
									},
									Source: "psirt@us.ibm.com",
									Rank:   2,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-38733"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{
										"cpe:2.3:a:redhat:openshift:-:*:*:*:*:*:*:*",
										"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
									},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 21.0.0, <= 21.0.7.3",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: ">= 23.0.0, <= 23.0.3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "ibm",
								Product: "robotic_process_automation",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2023-38733",
							CWE:    "CWE-532",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2023-38733",
							CWE:    "CWE-532",
							Source: "psirt@us.ibm.com",
							Type:   "Secondary",
						},
					),
				},
			},
		},
		{
			name:     "can process entries when the platform CPE is first",
			fixture:  "test-fixtures/CVE-2023-45283-platform-cpe-first.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2023-45283",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2023, 12, 14, 10, 15, 7, 947000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2023, 11, 9, 17, 15, 8, 757000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-45283",
							Assigners:   []string{"security@golang.org"},
							Description: "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
								},
								{
									URL:  "http://www.openwall.com/lists/oss-security/2023/12/05/2",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/cl/540277",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/cl/541175",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/issue/63713",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/issue/64028",
									Tags: nil,
								},
								{
									URL:  "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
									Tags: []string{"issue-tracking", "mailing-list", "vendor-advisory"},
								},
								{
									URL:  "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
									Tags: nil,
								},
								{
									URL:  "https://pkg.go.dev/vuln/GO-2023-2185",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20231214-0008/",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-45283"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "< 1.20.11",
										},
										Fix: &grypeDB.Fix{
											Version: "1.20.11",
											State:   grypeDB.FixedStatus,
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: ">= 1.21.0-0, < 1.21.4",
										},
										Fix: &grypeDB.Fix{
											Version: "1.21.4",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "golang",
								Product: "go",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2023-45283",
							CWE:    "CWE-22",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "can process entries when the platform CPE is last",
			fixture:  "test-fixtures/CVE-2023-45283-platform-cpe-last.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2023-45283",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2023, 12, 14, 10, 15, 7, 947000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2023, 11, 9, 17, 15, 8, 757000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-45283",
							Assigners:   []string{"security@golang.org"},
							Description: "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
								},
								{
									URL:  "http://www.openwall.com/lists/oss-security/2023/12/05/2",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/cl/540277",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/cl/541175",
									Tags: nil,
								},
								{
									URL:  "https://go.dev/issue/63713",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://go.dev/issue/64028",
									Tags: nil,
								},
								{
									URL:  "https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
									Tags: []string{"issue-tracking", "mailing-list", "vendor-advisory"},
								},
								{
									URL:  "https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
									Tags: nil,
								},
								{
									URL:  "https://pkg.go.dev/vuln/GO-2023-2185",
									Tags: []string{"issue-tracking", "vendor-advisory"},
								},
								{
									URL:  "https://security.netapp.com/advisory/ntap-20231214-0008/",
									Tags: nil,
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-45283"},
								Qualifiers: &grypeDB.PackageQualifiers{
									PlatformCPEs: []string{"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
								},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "< 1.20.11",
										},
										Fix: &grypeDB.Fix{
											Version: "1.20.11",
											State:   grypeDB.FixedStatus,
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: ">= 1.21.0-0, < 1.21.4",
										},
										Fix: &grypeDB.Fix{
											Version: "1.21.4",
											State:   grypeDB.FixedStatus,
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "golang",
								Product: "go",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2023-45283",
							CWE:    "CWE-22",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name: "a simple list of OS matches",
			// note: this was modified relative to the upstream data to account for additional interesting cases
			fixture:  "test-fixtures/cve-2024-26663-standalone-os.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2024-26663",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2025, 1, 7, 17, 20, 30, 367000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2024, 4, 2, 7, 15, 43, 287000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2024-26663",
							Assigners:   []string{"416baaa9-dc9f-4396-8d5f-8c081fb06d67"},
							Description: "the description...",
							References: []grypeDB.Reference{
								{URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-26663"},
								{
									URL:  "https://git.kernel.org/stable/c/0cd331dfd6023640c9669d0592bc0fd491205f87",
									Tags: []string{"patch"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2024-26663"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 10.0",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "o",
								Vendor:  "debian",
								Product: "debian_linux",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2024-26663"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: ">= 4.9, < 4.19.307",
										},
										Fix: &grypeDB.Fix{
											State:   grypeDB.FixedStatus,
											Version: "4.19.307",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: ">= 6.7, < 6.7.5",
										},
										Fix: &grypeDB.Fix{
											State:   grypeDB.FixedStatus,
											Version: "6.7.5",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 6.8-rc1",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 6.8-rc2",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 6.8-rc3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "o",
								Vendor:  "linux",
								Product: "linux_kernel",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2024-26663",
							CWE:    "CWE-476",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "drops nodes with unsupported topology",
			fixture:  "test-fixtures/cve-2021-1566.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2021-1566",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2024, 11, 21, 5, 44, 38, 237000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2021, 6, 16, 18, 15, 8, 710000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2021-1566",
							Assigners:   []string{"psirt@cisco.com"},
							Description: "description.",
							References: []grypeDB.Reference{
								{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-1566"},
								{
									URL:  "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-cert-vali-n8L97RW",
									Tags: []string{"vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:N",
										Version: "2.0",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
								{
									Scheme: "CVSS",
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
										Version: "3.1",
									},
									Source: "psirt@cisco.com",
									Rank:   2,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.CWEHandle{
							CVE:    "CVE-2021-1566",
							CWE:    "CWE-296",
							Source: "psirt@cisco.com",
							Type:   "Secondary",
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2021-1566",
							CWE:    "CWE-295",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					), // important! we dropped all of the node criteria since the topology is unsupported
				},
			},
		},
		{
			name:     "considers non-standard CPE fields",
			fixture:  "test-fixtures/CVE-2008-3442.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2008-3442",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2008, 9, 5, 21, 43, 5, 500000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2008, 8, 1, 14, 41, 0, 0, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2008-3442",
							Assigners:   []string{"cve@mitre.org"},
							Description: "desc.",
							References:  []grypeDB.Reference{{URL: "https://nvd.nist.gov/vuln/detail/CVE-2008-3442"}},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2008-3442"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 10.0",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 7.0",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 8.0",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 8.1",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 9.0",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "winzip",
								Product: "winzip",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2008-3442"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "= 8.1",
										},
									},
									{
										Version: grypeDB.Version{
											Constraint: "= 9.0",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "winzip",
								Product: "winzip",
								Edition: "sr1",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2008-3442",
							CWE:    "CWE-94",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "https://github.com/anchore/grype/issues/2807#issuecomment-3101447594",
			fixture:  "test-fixtures/CVE-2004-0377.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2004-0377",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2025, 4, 3, 1, 3, 51, 193000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2004, 5, 4, 4, 0, 0, 0, time.UTC)),
						Status:        grypeDB.UnknownVulnerabilityStatus,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2004-0377",
							Assigners:   []string{"cve@mitre.org"},
							Description: "Buffer overflow in the win32_stat function for (1) ActiveState's ActivePerl and (2) Larry Wall's Perl before 5.8.3 allows local or remote attackers to execute arbitrary commands via filenames that end in a backslash character.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2004-0377",
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs:   []string{"CVE-2004-0377"},
								Ranges: nil,
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "activestate",
								Product: "activeperl",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2004-0377"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Constraint: "<= 5.8.3",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "larry_wall",
								Product: "perl",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2004-0377",
							CWE:    "NVD-CWE-Other",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
		{
			name:     "JVM packages version format detection",
			fixture:  "test-fixtures/jvm-packages.json",
			provider: "nvd",
			config:   defaultConfig(),
			want: []transformers.RelatedEntries{
				{
					VulnerabilityHandle: &grypeDB.VulnerabilityHandle{
						Name:          "CVE-2023-JVM-TEST",
						ProviderID:    "nvd",
						Provider:      expectedProvider("nvd"),
						ModifiedDate:  timeRef(time.Date(2024, 1, 23, 16, 32, 52, 103000000, time.UTC)),
						PublishedDate: timeRef(time.Date(2024, 1, 17, 0, 15, 51, 677000000, time.UTC)),
						Status:        grypeDB.VulnerabilityActive,
						BlobValue: &grypeDB.VulnerabilityBlob{
							ID:          "CVE-2023-JVM-TEST",
							Assigners:   []string{"cve@mitre.org"},
							Description: "Test vulnerability affecting JVM packages to demonstrate version format detection.",
							References: []grypeDB.Reference{
								{
									URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-JVM-TEST",
								},
								{
									URL:  "https://www.oracle.com/security-alerts/cpujan2024.html",
									Tags: []string{"patch", "vendor-advisory"},
								},
							},
							Severities: []grypeDB.Severity{
								{
									Scheme: grypeDB.SeveritySchemeCVSS,
									Value: grypeDB.CVSSSeverity{
										Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
										Version: "3.1",
									},
									Source: "nvd@nist.gov",
									Rank:   1,
								},
							},
						},
					},
					Related: relatedEntries(
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-JVM-TEST"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Type:       "jvm",
											Constraint: "= 17.0.10",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "adoptium",
								Product: "java",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-JVM-TEST"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Type:       "jvm",
											Constraint: "= 21.0.2",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "azul",
								Product: "zulu",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-JVM-TEST"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Type:       "jvm",
											Constraint: "= 17.0.10",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "eclipse",
								Product: "openjdk",
							},
						},
						grypeDB.AffectedCPEHandle{
							BlobValue: &grypeDB.PackageBlob{
								CVEs: []string{"CVE-2023-JVM-TEST"},
								Ranges: []grypeDB.Range{
									{
										Version: grypeDB.Version{
											Type:       "jvm",
											Constraint: "= 11.0.22",
										},
									},
									{
										Version: grypeDB.Version{
											Type:       "jvm",
											Constraint: "= 8u401",
										},
									},
								},
							},
							CPE: &grypeDB.Cpe{
								Part:    "a",
								Vendor:  "oracle",
								Product: "jdk",
							},
						},
						grypeDB.CWEHandle{
							CVE:    "CVE-2023-JVM-TEST",
							CWE:    "CWE-79",
							Source: "nvd@nist.gov",
							Type:   "Primary",
						},
					),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vulns := loadFixture(t, test.fixture)

			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				if test.config == (Config{}) {
					test.config = defaultConfig()
				}
				entries, err := Transformer(test.config)(vuln, inputProviderState(test.provider))
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

func relatedEntries(items ...any) []any {
	return items
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.NVDVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer tests.CloseFile(f)

	entries, err := unmarshal.NvdVulnerabilityEntries(f)
	require.NoError(t, err)

	var vulns []unmarshal.NVDVulnerability
	for _, entry := range entries {
		vulns = append(vulns, entry.Cve)
	}

	return vulns
}

func timeRef(ti time.Time) *time.Time {
	return &ti
}

func TestIsValidCWE(t *testing.T) {
	tests := []struct {
		name     string
		cwe      string
		expected bool
	}{
		{
			name:     "empty string",
			cwe:      "",
			expected: false,
		},
		{
			name:     "NVD-CWE-noinfo",
			cwe:      "NVD-CWE-noinfo",
			expected: false,
		},
		{
			name:     "NVD-CWE-Other",
			cwe:      "NVD-CWE-Other",
			expected: true,
		},
		{
			name:     "valid CWE with single digit",
			cwe:      "CWE-1",
			expected: true,
		},
		{
			name:     "valid CWE with multiple digits",
			cwe:      "CWE-123",
			expected: true,
		},
		{
			name:     "valid CWE-79",
			cwe:      "CWE-79",
			expected: true,
		},
		{
			name:     "valid CWE-89",
			cwe:      "CWE-89",
			expected: true,
		},
		{
			name:     "invalid CWE without prefix",
			cwe:      "123",
			expected: false,
		},
		{
			name:     "invalid CWE without number",
			cwe:      "CWE-",
			expected: false,
		},
		{
			name:     "invalid CWE with letters",
			cwe:      "CWE-ABC",
			expected: false,
		},
		{
			name:     "invalid lowercase cwe",
			cwe:      "cwe-123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidCWE(tt.cwe)
			if got != tt.expected {
				t.Errorf("isValidCWE(%q) = %v, want %v", tt.cwe, got, tt.expected)
			}
		})
	}
}

func TestGetReferences(t *testing.T) {
	tests := []struct {
		name     string
		vuln     unmarshal.NVDVulnerability
		expected []grypeDB.Reference
	}{
		{
			name: "no upstream references - only canonical NVD URL",
			vuln: unmarshal.NVDVulnerability{
				ID:         "CVE-2023-12345",
				References: []nvd.Reference{},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
			},
		},
		{
			name: "single unique reference",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com/advisory", Tags: []string{"patch", "vendor-advisory"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com/advisory", Tags: []string{"patch", "vendor-advisory"}},
			},
		},
		{
			name: "multiple unique references",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com/advisory", Tags: []string{"patch"}},
					{URL: "https://github.com/project/issues/123", Tags: []string{"issue-tracking"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com/advisory", Tags: []string{"patch"}},
				{URL: "https://github.com/project/issues/123", Tags: []string{"issue-tracking"}},
			},
		},
		{
			name: "exact duplicate references",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: []string{"patch", "vendor-advisory"}},
					{URL: "https://example.com", Tags: []string{"patch", "vendor-advisory"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"patch", "vendor-advisory"}},
			},
		},
		{
			name: "duplicate with tags in different order (congruent sets)",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: []string{"patch", "vendor-advisory"}},
					{URL: "https://example.com", Tags: []string{"vendor-advisory", "patch"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"patch", "vendor-advisory"}},
			},
		},
		{
			name: "same URL with different tags - keep both",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: []string{"patch"}},
					{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"patch"}},
				{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
			},
		},
		{
			name: "same URL with and without tags - keep both",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: []string{"patch"}},
					{URL: "https://example.com", Tags: nil},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"patch"}},
				{URL: "https://example.com"},
			},
		},
		{
			name: "duplicate canonical NVD URL in upstream data",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345", Tags: nil},
					{URL: "https://example.com/advisory", Tags: []string{"vendor-advisory"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com/advisory", Tags: []string{"vendor-advisory"}},
			},
		},
		{
			name: "empty URL in upstream data - should be filtered",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "", Tags: []string{"patch"}},
					{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
			},
		},
		{
			name: "multiple duplicates among many references",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com/1", Tags: []string{"patch"}},
					{URL: "https://example.com/2", Tags: []string{"vendor-advisory"}},
					{URL: "https://example.com/1", Tags: []string{"patch"}},
					{URL: "https://example.com/3", Tags: nil},
					{URL: "https://example.com/2", Tags: []string{"vendor-advisory"}},
					{URL: "https://example.com/3", Tags: []string{}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com/1", Tags: []string{"patch"}},
				{URL: "https://example.com/2", Tags: []string{"vendor-advisory"}},
				{URL: "https://example.com/3"},
			},
		},
		{
			name: "preserves order of first occurrence",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com/1", Tags: []string{"patch"}},
					{URL: "https://example.com/2", Tags: []string{"advisory"}},
					{URL: "https://example.com/3", Tags: []string{"exploit"}},
					{URL: "https://example.com/1", Tags: []string{"patch"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com/1", Tags: []string{"patch"}},
				{URL: "https://example.com/2", Tags: []string{"advisory"}},
				{URL: "https://example.com/3", Tags: []string{"exploit"}},
			},
		},
		{
			name: "complex real-world scenario with duplicates and tag reordering",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
					{URL: "https://github.com/project/issues/123", Tags: []string{"issue-tracking", "third-party-advisory"}},
					{URL: "https://security.vendor.com/advisory", Tags: []string{"patch", "vendor-advisory"}},
					{URL: "https://github.com/project/issues/123", Tags: []string{"third-party-advisory", "issue-tracking"}},
					{URL: "https://lists.vendor.com/announce", Tags: []string{"mailing-list"}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://github.com/project/issues/123", Tags: []string{"issue-tracking", "third-party-advisory"}},
				{URL: "https://security.vendor.com/advisory", Tags: []string{"patch", "vendor-advisory"}},
				{URL: "https://lists.vendor.com/announce", Tags: []string{"mailing-list"}},
			},
		},
		{
			name: "references with nil tags vs empty tags - treated as identical",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: nil},
					{URL: "https://example.com", Tags: []string{}},
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com"},
			},
		},
		{
			name: "duplicate after different tags on same URL - exposes logic bug",
			vuln: unmarshal.NVDVulnerability{
				ID: "CVE-2023-12345",
				References: []nvd.Reference{
					{URL: "https://example.com", Tags: []string{"patch"}},
					{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
					{URL: "https://example.com", Tags: []string{"patch"}}, // duplicate of first
				},
			},
			expected: []grypeDB.Reference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
				{URL: "https://example.com", Tags: []string{"patch"}},
				{URL: "https://example.com", Tags: []string{"vendor-advisory"}},
				// Should NOT have a duplicate "patch" entry here
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getReferences(tt.vuln)

			if diff := cmp.Diff(tt.expected, actual, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("getReferences() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
