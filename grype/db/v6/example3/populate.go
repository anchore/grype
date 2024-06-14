package main

func populateTestFixture() []Vulnerability {
	vulns := []Vulnerability{
		{
			SchemaVersion: "1.0",
			Name:          "VULN-0001",
			Modified:      "2024-01-01",
			Published:     "2024-01-01",
			Withdrawn:     "",
			Aliases: &[]Alias{
				{Alias: "ALIAS-0001"},
			},
			Related: &[]Related{
				{Related: "RELATED-0001"},
			},
			Summary: "Summary of vulnerability 1",
			Details: "Detailed description of vulnerability 1",
			Severity: &[]Severity{
				{Type: "High", Score: "9.0"},
			},
			Affected: &[]Affected{},
			References: &[]Reference{
				{Type: "Web", URL: "https://example.com/vuln-0001"},
			},
			Credits: &[]Credit{
				{Name: "Researcher 1", Contact: &[]Contact{{Contact: "contact1@example.com"}}, Type: "Reporter"},
			},
			//DatabaseSpecific: JSONB{Data: map[string]interface{}{"key1": "value1"}},
			DbSpecificNvd: &DbSpecificNvd{
				VulnStatus:            "active",
				CisaExploitAdd:        "yes",
				CisaActionDue:         "never",
				CisaRequiredAction:    "nope",
				CisaVulnerabilityName: "cisa-1234",
			},
		},
		{
			SchemaVersion: "1.0",
			Name:          "VULN-0002",
			Modified:      "2024-01-01",
			Published:     "2024-01-01",
			Withdrawn:     "",
			Aliases: &[]Alias{
				{Alias: "ALIAS-0001"},
			},
			Related: &[]Related{
				{Related: "RELATED-0002"},
			},
			Summary: "Summary of vulnerability 2",
			Details: "Detailed description of vulnerability 2",
			Severity: &[]Severity{
				{Type: "Medium", Score: "5.0"},
			},
			Affected: &[]Affected{
				{
					Package: &Package{
						Ecosystem: "npm",
						Name:      "package2",
						Purl:      "pkg:npm/package2@1.0.0",
					},
					Severity: &[]AffectedSeverity{
						{Type: "Medium", Score: "5.0"},
					},
					Ranges: &[]Range{
						{
							Type: "Git",
							Repo: "https://github.com/example/repo",
							Events: &[]RangeEvent{
								{Introduced: "1.0.0", Fixed: "1.0.1"},
							},
							//DatabaseSpecific: JSONB{Data: map[string]interface{}{"range_key": "range_value"}},
						},
					},
					Versions: &[]Version{
						{Version: "1.0.0"},
					},
					//EcosystemSpecific: JSONB{Data: map[string]interface{}{"ecosystem_key": "ecosystem_value"}},
					//DatabaseSpecific:  JSONB{Data: map[string]interface{}{"db_key": "db_value"}},
				},
			},
			References: &[]Reference{
				{Type: "Web", URL: "https://example.com/vuln-0002"},
			},
			Credits: &[]Credit{
				{Name: "Researcher 2", Contact: &[]Contact{{Contact: "contact2@example.com"}}, Type: "Reporter"},
			},
			//DatabaseSpecific: JSONB{Data: map[string]interface{}{"key2": "value2"}},
		},
		{
			SchemaVersion: "1.0",
			Name:          "VULN-0003",
			Modified:      "2024-01-01",
			Published:     "2024-01-01",
			Withdrawn:     "",
			Aliases: &[]Alias{
				{Alias: "ALIAS-0003"},
			},
			Related: &[]Related{
				{Related: "RELATED-0003"},
			},
			Summary: "Summary of vulnerability 3",
			Details: "Detailed description of vulnerability 3",
			Severity: &[]Severity{
				{Type: "Low", Score: "3.0"},
			},
			Affected: &[]Affected{
				{
					Package: &Package{
						Ecosystem: "maven",
						Name:      "package3",
						Purl:      "pkg:maven/package3@1.0.0",
					},
					Severity: &[]AffectedSeverity{
						{Type: "Low", Score: "3.0"},
					},
					Ranges: &[]Range{
						{
							Type: "Git",
							Repo: "https://github.com/example/repo",
							Events: &[]RangeEvent{
								{Introduced: "1.0.0", Fixed: "1.0.1"},
							},
							//DatabaseSpecific: JSONB{Data: map[string]interface{}{"range_key": "range_value"}},
						},
					},
					Versions: &[]Version{
						{Version: "1.0.0"},
					},
					//EcosystemSpecific: JSONB{Data: map[string]interface{}{"ecosystem_key": "ecosystem_value"}},
					//DatabaseSpecific:  JSONB{Data: map[string]interface{}{"db_key": "db_value"}},
				},
				{
					Package: &Package{
						Ecosystem: "pypi",
						Name:      "package4",
						Purl:      "pkg:pypi/package4@2.0.0",
					},
					Severity: &[]AffectedSeverity{
						{Type: "Low", Score: "3.0"},
					},
					Ranges: &[]Range{
						{
							Type: "Git",
							Repo: "https://github.com/example/repo",
							Events: &[]RangeEvent{
								{Introduced: "2.0.0", Fixed: "2.0.1"},
							},
							//DatabaseSpecific: JSONB{Data: map[string]interface{}{"range_key": "range_value"}},
						},
					},
					Versions: &[]Version{
						{Version: "2.0.0"},
					},
					//EcosystemSpecific: JSONB{Data: map[string]interface{}{"ecosystem_key": "ecosystem_value"}},
					//DatabaseSpecific:  JSONB{Data: map[string]interface{}{"db_key": "db_value"}},
				},
			},
			References: &[]Reference{
				{Type: "Web", URL: "https://example.com/vuln-0003"},
			},
			Credits: &[]Credit{
				{Name: "Researcher 3", Contact: &[]Contact{{Contact: "contact3@example.com"}}, Type: "Reporter"},
			},
			//DatabaseSpecific: JSONB{Data: map[string]interface{}{"key3": "value3"}},
		},
	}

	return vulns
}
