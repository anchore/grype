package nvd

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
	testUtils "github.com/anchore/grype/grype/db/internal/tests"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/platformcpe"
	"github.com/anchore/grype/grype/version"
)

func TestUnmarshalNVDVulnerabilitiesEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/unmarshal-test.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.NvdVulnerabilityEntries(f)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestParseAllNVDVulnerabilityEntries(t *testing.T) {

	tests := []struct {
		name       string
		config     Config
		numEntries int
		fixture    string
		vulns      []grypeDB.Vulnerability
		metadata   grypeDB.VulnerabilityMetadata
	}{
		{
			name:       "AppVersionRange",
			numEntries: 1,
			fixture:    "test-fixtures/version-range.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2018-5487",
					PackageName: "oncommand_unified_manager",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint: ">= 7.2, <= 7.3",
					VersionFormat:     "unknown", // TODO: this should reference a format, yes? (not a string)
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:oncommand_unified_manager:*:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-5487",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-5487",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "Critical",
				URLs:         []string{"https://security.netapp.com/advisory/ntap-20180523-0001/"},
				Description:  "NetApp OnCommand Unified Manager for Linux versions 7.2 through 7.3 ship with the Java Management Extension Remote Method Invocation (JMX RMI) service bound to the network, and are susceptible to unauthenticated remote code execution.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							10,
							6.4,
						),
						Vector:  "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							9.8,
							3.9,
							5.9,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "App+OS",
			numEntries: 1,
			fixture:    "test-fixtures/single-package-multi-distro.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2018-1000222",
					PackageName:       "libgd",
					VersionConstraint: "= 2.2.5",
					VersionFormat:     "unknown", // TODO: this should reference a format, yes? (not a string)
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:libgd:libgd:2.2.5:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				// TODO: Question: should this match also the OS's? (as in the vulnerable_cpes list)... this seems wrong!
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-1000222",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-1000222",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs:         []string{"https://github.com/libgd/libgd/issues/447", "https://lists.debian.org/debian-lts-announce/2019/01/msg00028.html", "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3CZ2QADQTKRHTGB2AHD7J4QQNDLBEMM6/", "https://security.gentoo.org/glsa/201903-18", "https://usn.ubuntu.com/3755-1/"},
				Description:  "Libgd version 2.2.5 contains a Double Free Vulnerability vulnerability in gdImageBmpPtr Function that can result in Remote Code Execution . This attack appear to be exploitable via Specially Crafted Jpeg Image can trigger double free. This vulnerability appears to have been fixed in after commit ac16bdf2d41724b5a65255d4c28fb0ec46bc42f5.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							6.8,
							8.6,
							6.4,
						),
						Vector:  "AV:N/AC:M/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							8.8,
							2.8,
							5.9,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "AppCompoundVersionRange",
			numEntries: 1,
			fixture:    "test-fixtures/compound-pkg.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2018-10189",
					PackageName:       "mautic",
					VersionConstraint: ">= 1.0.0, <= 1.4.1 || >= 2.0.0, < 2.13.0",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:mautic:mautic:*:*:*:*:*:*:*:*"}, // note: entry was dedupicated
					Fix: grypeDB.Fix{
						Versions: []string{"2.13.0"},
						State:    "fixed",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-10189",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2018-10189",
				Namespace:    "nvd:cpe",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs:         []string{"https://github.com/mautic/mautic/releases/tag/2.13.0"},
				Description:  "An issue was discovered in Mautic 1.x and 2.x before 2.13.0. It is possible to systematically emulate tracking cookies per contact due to tracking the contact by their auto-incremented ID. Thus, a third party can manipulate the cookie value with +1 to systematically assume being tracked as each contact in Mautic. It is then possible to retrieve information about the contact through forms that have progressive profiling enabled.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							5,
							10,
							2.9,
						),
						Vector:  "AV:N/AC:L/Au:N/C:P/I:N/A:N",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							3.9,
							3.6,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			// we always keep the metadata even though there are no vulnerability entries for it
			name:       "InvalidCPE",
			numEntries: 1,
			fixture:    "test-fixtures/invalid_cpe.json",
			vulns:      nil,
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2015-8978",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2015-8978",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"http://cpansearch.perl.org/src/PHRED/SOAP-Lite-1.20/Changes",
					"http://www.securityfocus.com/bid/94487",
				},
				Description: "In Soap Lite (aka the SOAP::Lite extension for Perl) 1.14 and earlier, an example attack consists of defining 10 or more XML entities, each defined as consisting of 10 of the previous entity, with the document consisting of a single instance of the largest entity, which expands to one billion copies of the first entity. The amount of computer memory used for handling an external SOAP call would likely exceed that available to the process parsing the XML.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							5,
							10,
							2.9,
						),
						Vector:  "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7.5,
							3.9,
							3.6,
						),
						Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						Version: "3.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "With Platform CPE",
			numEntries: 1,
			fixture:    "test-fixtures/platform-cpe.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2022-26488",
					PackageName:       "active_iq_unified_manager",
					VersionConstraint: "",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:active_iq_unified_manager:-:*:*:*:*:windows:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				{
					ID:                "CVE-2022-26488",
					PackageName:       "ontap_select_deploy_administration_utility",
					VersionConstraint: "",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs:              []string{"cpe:2.3:a:netapp:ontap_select_deploy_administration_utility:-:*:*:*:*:*:*:*"},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
				{
					ID:          "CVE-2022-26488",
					PackageName: "python",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint: "<= 3.7.12 || >= 3.8.0, <= 3.8.12 || >= 3.9.0, <= 3.9.10 || >= 3.10.0, <= 3.10.2 || = 3.11.0-alpha1 || = 3.11.0-alpha2 || = 3.11.0-alpha3 || = 3.11.0-alpha4 || = 3.11.0-alpha5 || = 3.11.0-alpha6",
					VersionFormat:     "unknown",
					Namespace:         "nvd:cpe",
					CPEs: []string{
						"cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha1:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha2:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha3:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha4:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha5:*:*:*:*:*:*",
						"cpe:2.3:a:python:python:3.11.0:alpha6:*:*:*:*:*:*",
					},
					Fix: grypeDB.Fix{
						State: "unknown",
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2022-26488",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2022-26488",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"https://mail.python.org/archives/list/security-announce@python.org/thread/657Z4XULWZNIY5FRP3OWXHYKUSIH6DMN/",
					"https://security.netapp.com/advisory/ntap-20220419-0005/",
				},
				Description: "In Python before 3.10.3 on Windows, local users can gain privileges because the search path is inadequately secured. The installer may allow a local attacker to add user-writable directories to the system search path. To exploit, an administrator must have installed Python for all users and enabled PATH entries. A non-administrative user can trigger a repair that incorrectly adds user-writable paths into PATH, enabling search-path hijacking of other users and system services. This affects Python (CPython) through 3.7.12, 3.8.x through 3.8.12, 3.9.x through 3.9.10, and 3.10.x through 3.10.2.",
				Cvss: []grypeDB.Cvss{
					{
						Metrics: grypeDB.NewCvssMetrics(
							4.4,
							3.4,
							6.4,
						),
						Vector:  "AV:L/AC:M/Au:N/C:P/I:P/A:P",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						Metrics: grypeDB.NewCvssMetrics(
							7,
							1,
							5.9,
						),
						Vector:  "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
						Version: "3.1",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "CVE-2022-0543 multiple platforms",
			numEntries: 1,
			fixture:    "test-fixtures/cve-2022-0543.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2022-0543",
					PackageName: "redis",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
					}},
					VersionConstraint:      "",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix:                    grypeDB.Fix{State: "unknown"},
					Advisories:             nil,
				},
				{
					ID:          "CVE-2022-0543",
					PackageName: "redis",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:canonical:ubuntu_linux:21.10:*:*:*:-:*:*:*",
					}},
					VersionConstraint:      "",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix:                    grypeDB.Fix{State: "unknown"},
					Advisories:             nil,
				},
				{
					ID:          "CVE-2022-0543",
					PackageName: "redis",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix:                    grypeDB.Fix{State: "unknown"},
					Advisories:             nil,
				},
				{
					ID:          "CVE-2022-0543",
					PackageName: "redis",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix:                    grypeDB.Fix{State: "unknown"},
					Advisories:             nil,
				},
				{
					ID:          "CVE-2022-0543",
					PackageName: "redis",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix:                    grypeDB.Fix{State: "unknown"},
					Advisories:             nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2022-0543",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "Critical",
				URLs: []string{
					"http://packetstormsecurity.com/files/166885/Redis-Lua-Sandbox-Escape.html",
					"https://bugs.debian.org/1005787",
					"https://lists.debian.org/debian-security-announce/2022/msg00048.html",
					"https://security.netapp.com/advisory/ntap-20220331-0004/",
					"https://www.debian.org/security/2022/dsa-5081",
					"https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce",
				},
				Description: "It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.",
				Cvss: []grypeDB.Cvss{
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(10, 10, 10),
						Vector:         "AV:N/AC:L/Au:N/C:C/I:C/A:C",
						Version:        "2.0",
						Source:         "nvd@nist.gov",
						Type:           "Primary",
					},
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(10, 3.9, 6),
						Vector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
						Version:        "3.1",
						Source:         "nvd@nist.gov",
						Type:           "Primary",
					},
				},
			},
		},
		{
			name:       "CVE-2020-10729 multiple platforms omitted top level config",
			numEntries: 1,
			fixture:    "test-fixtures/cve-2020-10729.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2020-10729",
					PackageName: "ansible_engine",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "< 2.9.6",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redhat:ansible_engine:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						Versions: []string{"2.9.6"},
						State:    "fixed",
					},
					Advisories: nil,
				},
				{
					ID:          "CVE-2020-10729",
					PackageName: "ansible_engine",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "< 2.9.6",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:redhat:ansible_engine:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						Versions: []string{"2.9.6"},
						State:    "fixed",
					},
					Advisories: nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-10729",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2020-10729",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "Medium",
				URLs: []string{
					"https://bugzilla.redhat.com/show_bug.cgi?id=1831089",
					"https://github.com/ansible/ansible/issues/34144",
					"https://www.debian.org/security/2021/dsa-4950",
				},
				Description: "A flaw was found in the use of insufficiently random values in Ansible. Two random password lookups of the same length generate the equal value as the template caching action for the same file since no re-evaluation happens. The highest threat from this vulnerability would be that all passwords are exposed at once for the file. This flaw affects Ansible Engine versions before 2.9.6.",
				Cvss: []grypeDB.Cvss{
					{
						VendorMetadata: nil,
						Metrics: grypeDB.NewCvssMetrics(
							2.1,
							3.9,
							2.9,
						),
						Vector:  "AV:L/AC:L/Au:N/C:P/I:N/A:N",
						Version: "2.0",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
					{
						VendorMetadata: nil,
						Metrics: grypeDB.NewCvssMetrics(
							5.5,
							1.8,
							3.6,
						),
						Vector:  "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
						Version: "3.1",
						Source:  "nvd@nist.gov",
						Type:    "Primary",
					},
				},
			},
		},
		{
			name:       "multiple platforms some are application",
			numEntries: 2,
			fixture:    "test-fixtures/multiple-platforms-with-application-cpe.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2023-38733",
					PackageName: "robotic_process_automation",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:a:redhat:openshift:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      ">= 21.0.0, <= 21.0.7.3 || >= 23.0.0, <= 23.0.3",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:ibm:robotic_process_automation:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						State: "unknown",
					},
					Advisories: nil,
				},
				{
					ID:          "CVE-2023-38733",
					PackageName: "robotic_process_automation",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      ">= 21.0.0, <= 21.0.7.3 || >= 23.0.0, <= 23.0.3",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:ibm:robotic_process_automation:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						State: "unknown",
					},
					Advisories: nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2023-38733",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2023-38733",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "Medium",
				URLs: []string{
					"https://exchange.xforce.ibmcloud.com/vulnerabilities/262293",
					"https://www.ibm.com/support/pages/node/7028223",
				},
				Description: "\nIBM Robotic Process Automation 21.0.0 through 21.0.7.1 and 23.0.0 through 23.0.1 server could allow an authenticated user to view sensitive information from installation logs.  IBM X-Force Id:  262293.\n\n",
				Cvss: []grypeDB.Cvss{
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(4.3, 2.8, 1.4),
						Vector:         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
						Version:        "3.1",
						Source:         "nvd@nist.gov",
						Type:           "Primary",
					},
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(4.3, 2.8, 1.4),
						Vector:         "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
						Version:        "3.1",
						Source:         "psirt@us.ibm.com",
						Type:           "Secondary",
					},
				},
			},
		},
		{
			name:       "Platform CPE first in CPE config list",
			numEntries: 1,
			fixture:    "test-fixtures/CVE-2023-45283-platform-cpe-first.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2023-45283",
					PackageName: "go",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "< 1.20.11 || >= 1.21.0-0, < 1.21.4",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						Versions: []string{"1.20.11", "1.21.4"},
						State:    "fixed",
					},
					Advisories: nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2023-45283",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"http://www.openwall.com/lists/oss-security/2023/12/05/2",
					"https://go.dev/cl/540277",
					"https://go.dev/cl/541175",
					"https://go.dev/issue/63713",
					"https://go.dev/issue/64028",
					"https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
					"https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
					"https://pkg.go.dev/vuln/GO-2023-2185",
					"https://security.netapp.com/advisory/ntap-20231214-0008/",
				},
				Description: "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
				Cvss: []grypeDB.Cvss{
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(7.5, 3.9, 3.6),
						Vector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Version:        "3.1",
						Source:         "nvd@nist.gov",
						Type:           "Primary",
					},
				},
			},
		},
		{
			name:       "Platform CPE last in CPE config list",
			numEntries: 1,
			fixture:    "test-fixtures/CVE-2023-45283-platform-cpe-last.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2023-45283",
					PackageName: "go",
					Namespace:   "nvd:cpe",
					PackageQualifiers: []qualifier.Qualifier{platformcpe.Qualifier{
						Kind: "platform-cpe",
						CPE:  "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
					}},
					VersionConstraint:      "< 1.20.11 || >= 1.21.0-0, < 1.21.4",
					VersionFormat:          "unknown",
					CPEs:                   []string{"cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"},
					RelatedVulnerabilities: nil,
					Fix: grypeDB.Fix{
						Versions: []string{"1.20.11", "1.21.4"},
						State:    "fixed",
					},
					Advisories: nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2023-45283",
				Namespace:    "nvd:cpe",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2023-45283",
				RecordSource: "nvdv2:nvdv2:cves",
				Severity:     "High",
				URLs: []string{
					"http://www.openwall.com/lists/oss-security/2023/12/05/2",
					"https://go.dev/cl/540277",
					"https://go.dev/cl/541175",
					"https://go.dev/issue/63713",
					"https://go.dev/issue/64028",
					"https://groups.google.com/g/golang-announce/c/4tU8LZfBFkY",
					"https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ",
					"https://pkg.go.dev/vuln/GO-2023-2185",
					"https://security.netapp.com/advisory/ntap-20231214-0008/",
				},
				Description: "The filepath package does not recognize paths with a \\??\\ prefix as special. On Windows, a path beginning with \\??\\ is a Root Local Device path equivalent to a path beginning with \\\\?\\. Paths with a \\??\\ prefix may be used to access arbitrary locations on the system. For example, the path \\??\\c:\\x is equivalent to the more common path c:\\x. Before fix, Clean could convert a rooted path such as \\a\\..\\??\\b into the root local device path \\??\\b. Clean will now convert this to .\\??\\b. Similarly, Join(\\, ??, b) could convert a seemingly innocent sequence of path elements into the root local device path \\??\\b. Join will now convert this to \\.\\??\\b. In addition, with fix, IsAbs now correctly reports paths beginning with \\??\\ as absolute, and VolumeName correctly reports the \\??\\ prefix as a volume name. UPDATE: Go 1.20.11 and Go 1.21.4 inadvertently changed the definition of the volume name in Windows paths starting with \\?, resulting in filepath.Clean(\\?\\c:) returning \\?\\c: rather than \\?\\c:\\ (among other effects). The previous behavior has been restored.",
				Cvss: []grypeDB.Cvss{
					{
						VendorMetadata: nil,
						Metrics:        grypeDB.NewCvssMetrics(7.5, 3.9, 3.6),
						Vector:         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						Version:        "3.1",
						Source:         "nvd@nist.gov",
						Type:           "Primary",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.config == (Config{}) {
				test.config = defaultConfig()
			}
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, f.Close())
			})

			entries, err := unmarshal.NvdVulnerabilityEntries(f)
			require.NoError(t, err)

			var vulns []grypeDB.Vulnerability
			for _, entry := range entries {
				dataEntries, err := transform(test.config, entry.Cve)
				require.NoError(t, err)

				for _, entry := range dataEntries {
					switch vuln := entry.Data.(type) {
					case grypeDB.Vulnerability:
						vulns = append(vulns, vuln)
					case grypeDB.VulnerabilityMetadata:
						// check metadata
						if diff := deep.Equal(test.metadata, vuln); diff != nil {
							for _, d := range diff {
								t.Errorf("metadata diff: %+v", d)
							}
						}
					default:
						t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
					}
				}
			}

			if diff := cmp.Diff(test.vulns, vulns); diff != "" {
				t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetVersionFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		cpes     []string
		expected version.Format
	}{
		{
			name:     "detects JVM format from name",
			input:    "java_se",
			cpes:     []string{},
			expected: version.JVMFormat,
		},
		{
			name:     "detects JVM format from CPEs",
			input:    "other_product",
			cpes:     []string{"cpe:2.3:a:oracle:openjdk:11:update53:*:*:*:*:*:*"},
			expected: version.JVMFormat,
		},
		{
			name:     "detects JVM format from another CPE (zulu)",
			input:    "other_product",
			cpes:     []string{"cpe:2.3:a:zula:zulu:15:*:*:*:*:*:*:*"},
			expected: version.JVMFormat,
		},
		{
			name:     "detects JVM format from another CPE (jdk)",
			input:    "other_product",
			cpes:     []string{"cpe:2.3:a:oracle:jdk:11.0:*:*:*:*:*:*:*"},
			expected: version.JVMFormat,
		},
		{
			name:     "detects JVM format from another CPE (jre)",
			input:    "other_product",
			cpes:     []string{"cpe:2.3:a:oracle:jre:11.0:*:*:*:*:*:*:*"},
			expected: version.JVMFormat,
		},
		{
			name:     "returns unknown format for non-JVM product and non-JVM CPEs",
			input:    "non_jvm_product",
			cpes:     []string{"cpe:2.3:a:some_other_product:product_name:1.0:*:*:*:*:*:*"},
			expected: version.UnknownFormat,
		},
		{
			name:     "handles invalid CPE gracefully",
			input:    "non_jvm_product",
			cpes:     []string{"invalid_cpe_format"},
			expected: version.UnknownFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := getVersionFormat(tt.input, tt.cpes)
			assert.Equal(t, tt.expected, format)
		})
	}
}

func TestGetFix(t *testing.T) {
	tests := []struct {
		name     string
		matches  []nvd.CpeMatch
		expected grypeDB.Fix
	}{
		{
			name: "Equals",
			matches: []nvd.CpeMatch{
				{
					Criteria:   "cpe:2.3:a:vendor:product:2.2.0:*:*:*:*:target:*:*",
					Vulnerable: true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "VersionEndExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndExcluding: strRef("2.3.0"),
					Vulnerable:          true,
				},
			},
			expected: grypeDB.Fix{
				Versions: []string{"2.3.0"},
				State:    "fixed",
			},
		},
		{
			name: "VersionEndIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:            "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionEndIncluding: strRef("2.3.0"),
					Vulnerable:          true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "VersionStartExcluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("2.3.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "VersionStartIncluding",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "Version Range",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "Multiple Version Ranges",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndIncluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("3.3.0"),
					VersionEndExcluding:   strRef("3.5.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: []string{"3.5.0"},
				State:    "fixed",
			},
		},
		{
			name: "Empty end exclude treated as unknown",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartExcluding: strRef("3.3.0"),
					VersionEndExcluding:   strRef(""),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "Multiple fixes with deduplication",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("3.3.0"),
					VersionEndExcluding:   strRef("3.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("0"),
					VersionEndExcluding:   strRef("1.7.0"),
					Vulnerable:            true,
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target-2:*:*",
					VersionStartIncluding: strRef("0"),
					VersionEndExcluding:   strRef("1.7.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: []string{"1.7.0", "3.5.0"},
				State:    "fixed",
			},
		},
		{
			name: "< version as end in a separate affected >= range",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndExcluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.5.0"),
					VersionEndExcluding:   strRef("3.5.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: []string{"3.5.0"},
				State:    "fixed",
			},
		},
		{
			name: "< version as start in a separate affected <= range",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndExcluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.1.0"),
					VersionEndIncluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "< range with same version affected == critera",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndExcluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:   "cpe:2.3:a:vendor:product:2.5.0:*:*:*:*:target:*:*",
					Vulnerable: true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
		{
			name: "< range with another unaffected entry",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndExcluding:   strRef("2.5.0"),
					Vulnerable:            true,
				},
				{
					Criteria:   "cpe:2.3:a:vendor:product:2.5.0:*:*:*:*:target:*:*",
					Vulnerable: false,
				},
			},
			expected: grypeDB.Fix{
				Versions: []string{"2.5.0"},
				State:    "fixed",
			},
		},
		{
			name: "treat * in < as unknown fix state",
			matches: []nvd.CpeMatch{
				{
					Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:target:*:*",
					VersionStartIncluding: strRef("2.3.0"),
					VersionEndExcluding:   strRef("*"),
					Vulnerable:            true,
				},
			},
			expected: grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := getFix(tt.matches, true)
			assert.Equal(t, tt.expected, fix)
		})

		t.Run(tt.name+" don't infer NVD fixes", func(t *testing.T) {
			fix := getFix(tt.matches, false)
			assert.Equal(t, grypeDB.Fix{
				Versions: nil,
				State:    "unknown",
			}, fix)
		})
	}
}
