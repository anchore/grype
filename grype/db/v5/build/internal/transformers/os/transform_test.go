package os

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	testUtils "github.com/anchore/grype/grype/db/internal/tests"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/build/internal/transformers"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier"
	"github.com/anchore/grype/grype/db/v5/pkg/qualifier/rpmmodularity"
)

func TestUnmarshalOSVulnerabilitiesEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/unmarshal-test.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.OSVulnerabilityEntries(f)
	require.NoError(t, err)

	assert.Len(t, entries, 3)

}

func TestParseVulnerabilitiesEntry(t *testing.T) {
	tests := []struct {
		name       string
		numEntries int
		fixture    string
		vulns      []grypeDB.Vulnerability
		metadata   grypeDB.VulnerabilityMetadata
	}{
		{
			name:       "Amazon",
			numEntries: 1,
			fixture:    "test-fixtures/amzn.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "ALAS-2018-1106",
					VersionConstraint: "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-14648",
							Namespace: "nvd:cpe",
						},
					},
					PackageName: "389-ds-base",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					Namespace: "amazon:distro:amazonlinux:2",
					Fix: grypeDB.Fix{
						Versions: []string{"1.3.8.4-15.amzn2.0.1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "ALAS-2018-1106",
					VersionConstraint: "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-14648",
							Namespace: "nvd:cpe",
						},
					},
					PackageName: "389-ds-base-debuginfo",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					Namespace: "amazon:distro:amazonlinux:2",
					Fix: grypeDB.Fix{
						Versions: []string{"1.3.8.4-15.amzn2.0.1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "ALAS-2018-1106",
					VersionConstraint: "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-14648",
							Namespace: "nvd:cpe",
						},
					},
					PackageName: "389-ds-base-devel",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					Namespace: "amazon:distro:amazonlinux:2",
					Fix: grypeDB.Fix{
						Versions: []string{"1.3.8.4-15.amzn2.0.1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "ALAS-2018-1106",
					VersionConstraint: "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-14648",
							Namespace: "nvd:cpe",
						},
					},
					PackageName: "389-ds-base-libs",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					Namespace: "amazon:distro:amazonlinux:2",
					Fix: grypeDB.Fix{
						Versions: []string{"1.3.8.4-15.amzn2.0.1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "ALAS-2018-1106",
					VersionConstraint: "< 1.3.8.4-15.amzn2.0.1",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-14648",
							Namespace: "nvd:cpe",
						},
					},
					PackageName: "389-ds-base-snmp",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					Namespace: "amazon:distro:amazonlinux:2",
					Fix: grypeDB.Fix{
						Versions: []string{"1.3.8.4-15.amzn2.0.1"},
						State:    grypeDB.FixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "ALAS-2018-1106",
				Namespace:    "amazon:distro:amazonlinux:2",
				DataSource:   "https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html",
				RecordSource: "vulnerabilities:amzn:2",
				Severity:     "Medium",
				URLs:         []string{"https://alas.aws.amazon.com/AL2/ALAS-2018-1106.html"},
			},
		},
		{
			name:       "Debian",
			numEntries: 1,
			fixture:    "test-fixtures/debian-8.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2008-7220",
					PackageName:       "asterisk",
					VersionConstraint: "< 1:1.6.2.0~rc3-1",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2008-7220",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"1:1.6.2.0~rc3-1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "CVE-2008-7220",
					PackageName:       "auth2db",
					VersionConstraint: "< 0.2.5-2+dfsg-1",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2008-7220",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0.2.5-2+dfsg-1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "CVE-2008-7220",
					PackageName:       "exaile",
					VersionConstraint: "< 0.2.14+debian-2.2",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2008-7220",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0.2.14+debian-2.2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "CVE-2008-7220",
					PackageName: "wordpress",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2008-7220",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						State: grypeDB.NotFixedState,
					},
					VersionConstraint: "",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2008-7220",
				Namespace:    "debian:distro:debian:8",
				DataSource:   "https://security-tracker.debian.org/tracker/CVE-2008-7220",
				RecordSource: "vulnerabilities:debian:8",
				Severity:     "High",
				URLs:         []string{"https://security-tracker.debian.org/tracker/CVE-2008-7220"},
				Description:  "",
			},
		},
		{
			name:       "RHEL",
			numEntries: 1,
			fixture:    "test-fixtures/rhel-8.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2020-6819",
					PackageName: "firefox",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 0:68.6.1-1.el8_1",
					VersionFormat:     "rpm",
					Namespace:         "redhat:distro:redhat:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-6819",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:68.6.1-1.el8_1"},
						State:    grypeDB.FixedState,
					},
					Advisories: []grypeDB.Advisory{
						{
							ID:   "RHSA-2020:1341",
							Link: "https://access.redhat.com/errata/RHSA-2020:1341",
						},
					},
				},
				{
					ID:          "CVE-2020-6819",
					PackageName: "thunderbird",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 0:68.7.0-1.el8_1",
					VersionFormat:     "rpm",
					Namespace:         "redhat:distro:redhat:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-6819",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:68.7.0-1.el8_1"},
						State:    grypeDB.FixedState,
					},
					Advisories: []grypeDB.Advisory{
						{
							ID:   "RHSA-2020:1495",
							Link: "https://access.redhat.com/errata/RHSA-2020:1495",
						},
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-6819",
				DataSource:   "https://access.redhat.com/security/cve/CVE-2020-6819",
				Namespace:    "redhat:distro:redhat:8",
				RecordSource: "vulnerabilities:rhel:8",
				Severity:     "Critical",
				URLs:         []string{"https://access.redhat.com/security/cve/CVE-2020-6819"},
				Description:  "A flaw was found in Mozilla Firefox. A race condition can occur while running the nsDocShell destructor causing a use-after-free memory issue. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.",
				Cvss: []grypeDB.Cvss{
					{
						Version: "3.1",
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
						Metrics: grypeDB.NewCvssMetrics(
							8.8,
							2.8,
							5.9,
						),
						VendorMetadata: transformers.VendorBaseMetrics{
							Status:       "verified",
							BaseSeverity: "High",
						},
					},
				},
			},
		},
		{
			name:       "RHEL with modularity",
			numEntries: 1,
			fixture:    "test-fixtures/rhel-8-modules.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:10",
					}},
					VersionConstraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
					VersionFormat:     "rpm",
					Namespace:         "redhat:distro:redhat:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:10.14-1.module+el8.2.0+7801+be0fed80"},
						State:    grypeDB.FixedState,
					},
					Advisories: []grypeDB.Advisory{
						{
							ID:   "RHSA-2020:3669",
							Link: "https://access.redhat.com/errata/RHSA-2020:3669",
						},
					},
				},
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:12",
					}},
					VersionConstraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
					VersionFormat:     "rpm",
					Namespace:         "redhat:distro:redhat:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:12.5-1.module+el8.3.0+9042+664538f4"},
						State:    grypeDB.FixedState,
					},
					Advisories: []grypeDB.Advisory{
						{
							ID:   "RHSA-2020:5620",
							Link: "https://access.redhat.com/errata/RHSA-2020:5620",
						},
					},
				},
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:9.6",
					}},
					VersionConstraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
					VersionFormat:     "rpm",
					Namespace:         "redhat:distro:redhat:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:9.6.20-1.module+el8.3.0+8938+7f0e88b6"},
						State:    grypeDB.FixedState,
					},
					Advisories: []grypeDB.Advisory{
						{
							ID:   "RHSA-2020:5619",
							Link: "https://access.redhat.com/errata/RHSA-2020:5619",
						},
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-14350",
				DataSource:   "https://access.redhat.com/security/cve/CVE-2020-14350",
				Namespace:    "redhat:distro:redhat:8",
				RecordSource: "vulnerabilities:rhel:8",
				Severity:     "Medium",
				URLs:         []string{"https://access.redhat.com/security/cve/CVE-2020-14350"},
				Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
				Cvss: []grypeDB.Cvss{
					{
						Version: "3.1",
						Vector:  "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
						Metrics: grypeDB.NewCvssMetrics(
							7.1,
							1.2,
							5.9,
						),
						VendorMetadata: transformers.VendorBaseMetrics{
							Status:       "verified",
							BaseSeverity: "High",
						},
					},
				},
			},
		},
		{
			name:       "RHEL EUS (ignore)",
			numEntries: 1,
			fixture:    "test-fixtures/rhel-8-eus.json",
			// intentionally creates no vulnerabilities to write to the DB
		},
		{
			name:       "Alpine",
			numEntries: 1,
			fixture:    "test-fixtures/alpine-3.9.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2018-19967",
					PackageName:       "xen",
					VersionConstraint: "< 4.11.1-r0",
					VersionFormat:     "apk",
					Namespace:         "alpine:distro:alpine:3.9",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2018-19967",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"4.11.1-r0"},
						State:    grypeDB.FixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2018-19967",
				DataSource:   "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967",
				Namespace:    "alpine:distro:alpine:3.9",
				RecordSource: "vulnerabilities:alpine:3.9",
				Severity:     "Medium",
				URLs:         []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19967"},
				Description:  "",
			},
		},
		{
			name:       "Oracle",
			numEntries: 1,
			fixture:    "test-fixtures/ol-8.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "ELSA-2020-2550",
					PackageName: "libexif",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 0:0.6.21-17.el8_2",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-13112",
							Namespace: "nvd:cpe",
						},
					},
					Namespace: "oracle:distro:oraclelinux:8",
					Fix: grypeDB.Fix{
						Versions: []string{"0:0.6.21-17.el8_2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ELSA-2020-2550",
					PackageName: "libexif-devel",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 0:0.6.21-17.el8_2",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-13112",
							Namespace: "nvd:cpe",
						},
					},
					Namespace: "oracle:distro:oraclelinux:8",
					Fix: grypeDB.Fix{
						Versions: []string{"0:0.6.21-17.el8_2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ELSA-2020-2550",
					PackageName: "libexif-dummy",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-13112",
							Namespace: "nvd:cpe",
						},
					},
					Namespace: "oracle:distro:oraclelinux:8",
					Fix: grypeDB.Fix{
						Versions: nil,
						State:    grypeDB.NotFixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "ELSA-2020-2550",
				DataSource:   "http://linux.oracle.com/errata/ELSA-2020-2550.html",
				Namespace:    "oracle:distro:oraclelinux:8",
				RecordSource: "vulnerabilities:ol:8",
				Severity:     "Medium",
				URLs:         []string{"http://linux.oracle.com/errata/ELSA-2020-2550.html", "http://linux.oracle.com/cve/CVE-2020-13112.html"},
			},
		},
		{
			name:       "Oracle Linux 8 with modularity",
			numEntries: 1,
			fixture:    "test-fixtures/ol-8-modules.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:10",
					}},
					VersionConstraint: "< 0:10.14-1.module+el8.2.0+7801+be0fed80",
					VersionFormat:     "rpm",
					Namespace:         "oracle:distro:oraclelinux:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:10.14-1.module+el8.2.0+7801+be0fed80"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:12",
					}},
					VersionConstraint: "< 0:12.5-1.module+el8.3.0+9042+664538f4",
					VersionFormat:     "rpm",
					Namespace:         "oracle:distro:oraclelinux:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:12.5-1.module+el8.3.0+9042+664538f4"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "CVE-2020-14350",
					PackageName: "postgresql",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "postgresql:9.6",
					}},
					VersionConstraint: "< 0:9.6.20-1.module+el8.3.0+8938+7f0e88b6",
					VersionFormat:     "rpm",
					Namespace:         "oracle:distro:oraclelinux:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2020-14350",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:9.6.20-1.module+el8.3.0+8938+7f0e88b6"},
						State:    grypeDB.FixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2020-14350",
				DataSource:   "https://access.redhat.com/security/cve/CVE-2020-14350",
				Namespace:    "oracle:distro:oraclelinux:8",
				RecordSource: "vulnerabilities:ol:8",
				Severity:     "Medium",
				URLs:         []string{"https://access.redhat.com/security/cve/CVE-2020-14350"},
				Description:  "A flaw was found in PostgreSQL, where some PostgreSQL extensions did not use the search_path safely in their installation script. This flaw allows an attacker with sufficient privileges to trick an administrator into executing a specially crafted script during the extension's installation or update. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.",
			},
		},
		{
			name:       "mariner linux 2.0",
			numEntries: 1,
			fixture:    "test-fixtures/mariner-20.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2021-37621",
					PackageName: "exiv2",
					Namespace:   "mariner:distro:mariner:2.0",
					PackageQualifiers: []qualifier.Qualifier{
						rpmmodularity.Qualifier{
							Kind: "rpm-modularity",
						},
					},
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-37621",
							Namespace: "nvd:cpe",
						},
					},
					VersionConstraint: "< 0:0.27.5-1.cm2",
					VersionFormat:     "rpm",
					Fix: grypeDB.Fix{
						Versions: []string{"0:0.27.5-1.cm2"},
						State:    grypeDB.FixedState,
					},
					Advisories: nil,
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2021-37621",
				Namespace:    "mariner:distro:mariner:2.0",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2021-37621",
				RecordSource: "vulnerabilities:mariner:2.0",
				Severity:     "Medium",
				URLs:         []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-37621"},
				Description:  "CVE-2021-37621 affecting package exiv2 for versions less than 0.27.5-1. An upgraded version of the package is available that resolves this issue.",
				Cvss:         nil,
			},
		},
		{
			name:       "azure linux 3",
			numEntries: 1,
			fixture:    "test-fixtures/azure-linux-3.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2023-29403",
					PackageName: "golang",
					Namespace:   "mariner:distro:azurelinux:3.0",
					PackageQualifiers: []qualifier.Qualifier{
						rpmmodularity.Qualifier{
							Kind: "rpm-modularity",
						},
					},
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2023-29403",
							Namespace: "nvd:cpe",
						},
					},
					VersionConstraint: "< 0:1.20.7-1.azl3",
					VersionFormat:     "rpm",
					Fix: grypeDB.Fix{
						Versions: []string{"0:1.20.7-1.azl3"},
						State:    grypeDB.FixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2023-29403",
				Namespace:    "mariner:distro:azurelinux:3.0",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2023-29403",
				RecordSource: "vulnerabilities:mariner:3.0",
				Severity:     "High",
				URLs:         []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-29403"},
				Description:  "CVE-2023-29403 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
			},
		},
		{
			name:       "mariner entry with version range",
			numEntries: 1,
			fixture:    "test-fixtures/mariner-range.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "CVE-2023-29404",
					PackageName: "golang",
					Namespace:   "mariner:distro:mariner:2.0",
					PackageQualifiers: []qualifier.Qualifier{
						rpmmodularity.Qualifier{
							Kind:   "rpm-modularity",
							Module: "",
						},
					},
					VersionConstraint: "> 0:1.19.0.cm2, < 0:1.20.7-1.cm2",
					VersionFormat:     "rpm",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2023-29404",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"0:1.20.7-1.cm2"},
						State:    grypeDB.FixedState,
					},
				},
			},
			metadata: grypeDB.VulnerabilityMetadata{
				ID:           "CVE-2023-29404",
				Namespace:    "mariner:distro:mariner:2.0",
				DataSource:   "https://nvd.nist.gov/vuln/detail/CVE-2023-29404",
				RecordSource: "vulnerabilities:mariner:2.0",
				Severity:     "Critical",
				URLs:         []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-29404"},
				Description:  "CVE-2023-29404 affecting package golang for versions less than 1.20.7-1. A patched version of the package is available.",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, f.Close())
			})

			entries, err := unmarshal.OSVulnerabilityEntries(f)
			assert.NoError(t, err)
			assert.Len(t, entries, 1)

			entry := entries[0]

			dataEntries, err := Transform(entry)
			assert.NoError(t, err)

			var vulns []grypeDB.Vulnerability
			for _, entry := range dataEntries {
				switch vuln := entry.Data.(type) {
				case grypeDB.Vulnerability:
					vulns = append(vulns, vuln)
				case grypeDB.VulnerabilityMetadata:
					assert.Equal(t, test.metadata, vuln)
				default:
					t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata: %+v", vuln)
				}
			}

			if diff := cmp.Diff(test.vulns, vulns); diff != "" {
				t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
			}

		})
	}

}

func TestParseVulnerabilitiesAllEntries(t *testing.T) {
	tests := []struct {
		name       string
		numEntries int
		fixture    string
		vulns      []grypeDB.Vulnerability
	}{
		{
			name:       "Debian",
			numEntries: 2,
			fixture:    "test-fixtures/debian-8-multiple-entries-for-same-package.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:                "CVE-2011-4623",
					PackageName:       "rsyslog",
					VersionConstraint: "< 5.7.4-1",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2011-4623",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"5.7.4-1"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:                "CVE-2008-5618",
					PackageName:       "rsyslog",
					VersionConstraint: "< 3.18.6-1",
					VersionFormat:     "dpkg",
					Namespace:         "debian:distro:debian:8",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2008-5618",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"3.18.6-1"},
						State:    grypeDB.FixedState,
					},
				},
			},
		},
		{
			name:       "Amazon",
			numEntries: 3,
			fixture:    "test-fixtures/amazon-multiple-kernel-advisories.json",
			vulns: []grypeDB.Vulnerability{
				{
					ID:          "ALAS-2021-1704",
					PackageName: "kernel-headers",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 4.14.246-187.474.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3653",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-3656",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-3732",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"4.14.246-187.474.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ALAS-2021-1704",
					PackageName: "kernel",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: "< 4.14.246-187.474.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3653",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-3656",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-3732",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"4.14.246-187.474.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ALASKERNEL-5.4-2022-007",
					PackageName: "kernel-headers",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: ">= 5.4, < 5.4.144-69.257.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3753",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-40490",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"5.4.144-69.257.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ALASKERNEL-5.4-2022-007",
					PackageName: "kernel",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: ">= 5.4, < 5.4.144-69.257.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3753",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-40490",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"5.4.144-69.257.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ALASKERNEL-5.10-2022-005",
					PackageName: "kernel-headers",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: ">= 5.10, < 5.10.62-55.141.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3753",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-40490",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"5.10.62-55.141.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
				{
					ID:          "ALASKERNEL-5.10-2022-005",
					PackageName: "kernel",
					PackageQualifiers: []qualifier.Qualifier{rpmmodularity.Qualifier{
						Kind:   "rpm-modularity",
						Module: "",
					}},
					VersionConstraint: ">= 5.10, < 5.10.62-55.141.amzn2",
					VersionFormat:     "rpm",
					Namespace:         "amazon:distro:amazonlinux:2",
					RelatedVulnerabilities: []grypeDB.VulnerabilityReference{
						{
							ID:        "CVE-2021-3753",
							Namespace: "nvd:cpe",
						},
						{
							ID:        "CVE-2021-40490",
							Namespace: "nvd:cpe",
						},
					},
					Fix: grypeDB.Fix{
						Versions: []string{"5.10.62-55.141.amzn2"},
						State:    grypeDB.FixedState,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.fixture)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, f.Close())
			})

			entries, err := unmarshal.OSVulnerabilityEntries(f)
			assert.NoError(t, err)
			assert.Len(t, entries, test.numEntries)

			var vulns []grypeDB.Vulnerability
			for _, entry := range entries {
				dataEntries, err := Transform(entry)
				assert.NoError(t, err)

				for _, entry := range dataEntries {
					switch vuln := entry.Data.(type) {
					case grypeDB.Vulnerability:
						vulns = append(vulns, vuln)
					case grypeDB.VulnerabilityMetadata:
					default:
						t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata: %+v", vuln)
					}
				}
			}

			if diff := cmp.Diff(test.vulns, vulns); diff != "" {
				t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
			}
		})
	}
}
