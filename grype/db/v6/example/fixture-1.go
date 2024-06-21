package main

import (
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"time"
)

func sp(s string) *string {
	return &s
}

func populateFixture1(store v6.Store) error {
	// Define providers
	ghsaProvider := &v6.Provider{
		ID:               "ghsa",
		Version:          "1.0",
		Processor:        "vunnel",
		DateCaptured:     timePtr(time.Now()),
		InputDigest:      "sha256:ghsadigest",
		InstanceCacheURL: "https://example.com/ghsa",
		SourceURL:        "https://github.com/advisories",
	}

	ubuntuProvider := &v6.Provider{
		ID:               "ubuntu",
		Version:          "20.04",
		Processor:        "vunnel",
		DateCaptured:     timePtr(time.Now()),
		InputDigest:      "sha256:ubuntudigest",
		InstanceCacheURL: "https://example.com/ubuntu",
		SourceURL:        "https://ubuntu.com/security/notices",
	}

	if err := store.AddProviders(ghsaProvider, ubuntuProvider); err != nil {
		return err
	}

	vulnerabilities := []*v6.Vulnerability{
		{
			ProviderID:    ghsaProvider.ID,
			Name:          "GHSA-xxxx-xxxx-xxxx1",
			Modified:      sp(time.Now().UTC().Format(time.RFC3339)),
			Published:     sp(time.Now().UTC().Format(time.RFC3339)),
			SummaryDigest: sp("sha256:exampledigest1"),
			DetailDigest:  sp("sha256:exampledetaildigest1"),
			Aliases: &[]v6.Alias{
				{Alias: "CVE-2024-12341"},
			},
			Severities: &[]v6.Severity{
				{Type: "CVSS_V3", Score: "5.0", Source: sp("nvd@nist.gov"), Priority: sp("secondary")},
			},
			References: &[]v6.Reference{
				{Type: "ADVISORY", URL: "https://example.com/GHSA-xxxx-xxxx-xxxx1"},
			},
			Affected: &[]v6.Affected{
				{
					Package: &v6.Package{
						Ecosystem:   "python",
						PackageName: "example-python-package1",
						Purls: &[]v6.Purl{
							{
								Scheme: "pkg",
								Type:   "python",
								//Namespace:  "",
								Name:    "example-python-package1",
								Version: "1.0.0",
								//SubPath:    "",
								//Qualifiers: nil,
							},
						},
					},
				},
			},
		},
		{
			ProviderID:    ghsaProvider.ID,
			Name:          "GHSA-xxxx-xxxx-xxxx2",
			Modified:      sp(time.Now().UTC().Format(time.RFC3339)),
			Published:     sp(time.Now().UTC().Format(time.RFC3339)),
			SummaryDigest: sp("sha256:exampledigest2"),
			DetailDigest:  sp("sha256:exampledetaildigest2"),
			Aliases: &[]v6.Alias{
				{Alias: "CVE-2024-12342"},
			},
			Severities: &[]v6.Severity{
				{Type: "CVSS_V3", Score: "7.5", Source: sp("nvd@nist.gov"), Priority: sp("primary")},
			},
			References: &[]v6.Reference{
				{Type: "ADVISORY", URL: "https://example.com/GHSA-xxxx-xxxx-xxxx2"},
			},
			Affected: &[]v6.Affected{
				{
					Package: &v6.Package{
						Ecosystem:   "golang",
						PackageName: "example-golang-package1",
						Purls: &[]v6.Purl{
							{
								Scheme: "pkg",
								Type:   "python",
								//Namespace:  "",
								Name:    "example-golang-package1",
								Version: "1.0.0",
								//SubPath:    "",
								//Qualifiers: nil,
							},
						},
						OperatingSystem: &v6.OperatingSystem{
							Name:         "ubuntu",
							MajorVersion: "18",
							MinorVersion: "04",
						},
					},
				},
			},
		},
		{
			ProviderID:    ubuntuProvider.ID,
			Name:          "CVE-2024-12343",
			Modified:      sp(time.Now().UTC().Format(time.RFC3339)),
			Published:     sp(time.Now().UTC().Format(time.RFC3339)),
			SummaryDigest: sp("sha256:exampledigest3"),
			DetailDigest:  sp("sha256:exampledetaildigest3"),
			Aliases: &[]v6.Alias{
				{Alias: "GHSA-xxxx-xxxx-xxxx3"},
			},
			Severities: &[]v6.Severity{
				{Type: "CVSS_V3", Score: "6.0", Source: sp("nvd@nist.gov"), Priority: sp("primary")},
			},
			References: &[]v6.Reference{
				{Type: "ADVISORY", URL: "https://example.com/CVE-2024-12343"},
			},
			Affected: &[]v6.Affected{
				{
					Package: &v6.Package{
						Ecosystem:   "python",
						PackageName: "example-python-package2",
						Purls: &[]v6.Purl{
							{
								Scheme: "pkg",
								Type:   "python",
								//Namespace:  "",
								Name:    "example-python-package2",
								Version: "1.0.0",
								//SubPath:    "",
								//Qualifiers: nil,
							},
						},
						OperatingSystem: &v6.OperatingSystem{
							Name:         "ubuntu",
							MajorVersion: "20",
							MinorVersion: "04",
						},
					},
				},
			},
		},
	}

	for i := 0; i < 7; i++ {
		vulnerabilities = append(vulnerabilities, &v6.Vulnerability{
			ProviderID:    ghsaProvider.ID,
			Name:          fmt.Sprintf("GHSA-xxxx-xxxx-xxxx%d", i+3),
			Modified:      sp(time.Now().UTC().Format(time.RFC3339)),
			Published:     sp(time.Now().UTC().Format(time.RFC3339)),
			SummaryDigest: sp(fmt.Sprintf("sha256:exampledigest%d", i+3)),
			DetailDigest:  sp(fmt.Sprintf("sha256:exampledetaildigest%d", i+3)),
			Aliases: &[]v6.Alias{
				{Alias: fmt.Sprintf("CVE-2024-1234%d", i+3)},
			},
			Severities: &[]v6.Severity{
				{Type: "CVSS_V3", Score: "4.0", Source: sp("nvd@nist.gov"), Priority: sp("primary")},
			},
			References: &[]v6.Reference{
				{Type: "ADVISORY", URL: fmt.Sprintf("https://example.com/GHSA-xxxx-xxxx-xxxx%d", i+3)},
			},
			Affected: &[]v6.Affected{
				{
					Package: &v6.Package{
						Ecosystem:   "python",
						PackageName: fmt.Sprintf("example-python-package%d", i+3),
						Purls: &[]v6.Purl{
							{
								Scheme: "pkg",
								Type:   "python",
								//Namespace:  "",
								Name:    fmt.Sprintf("example-python-package%d", i+3),
								Version: "1.0.0",
								//SubPath:    "",
								//Qualifiers: nil,
							},
						},
						OperatingSystem: &v6.OperatingSystem{
							Name:         "ubuntu",
							MajorVersion: "20",
							MinorVersion: "04",
						},
					},
				},
			},
		})
	}

	if err := store.AddVulnerabilities(vulnerabilities...); err != nil {
		return fmt.Errorf("failed to add vulnerabilities: %w", err)
	}

	//if err := store.AddAffected(affectedEntries...); err != nil {
	//	return fmt.Errorf("failed to add affected entries: %w", err)
	//}

	return nil
}

func timePtr(t time.Time) *time.Time {
	return &t
}
