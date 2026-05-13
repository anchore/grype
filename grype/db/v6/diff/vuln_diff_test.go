package diff

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/db/v6/testdb"
)

func Test_vulnDiff(t *testing.T) {
	type changes []any
	type added []VulnerabilityID
	type modified []VulnerabilityID
	type removed []VulnerabilityID

	v := func(provider, id string) VulnerabilityID {
		return VulnerabilityID{Provider: provider, ID: id}
	}
	kevOrEpss := func(id string) VulnerabilityID {
		return VulnerabilityID{ID: id}
	}

	tests := []struct {
		name          string
		oldDB         []string
		newDB         []string
		include       Includes
		epssThreshold float64
		expected      changes
	}{
		// ── no-change cases ────────────────────────────────────────────────
		{
			name:     "no-changes-vuln-only",
			oldDB:    []string{"cve-2025-24456"},
			newDB:    []string{"cve-2025-24456"},
			include:  Includes{Vulns: true},
			expected: changes{},
		},
		{
			name:     "no-changes-with-kev",
			oldDB:    []string{"cve-2020-15415"},
			newDB:    []string{"cve-2020-15415"},
			include:  Includes{Vulns: true, KEV: true},
			expected: changes{},
		},
		{
			name:          "no-changes-with-epss",
			oldDB:         []string{"cve-2022-38178"},
			newDB:         []string{"cve-2022-38178"},
			include:       Includes{Vulns: true, EPSS: true},
			epssThreshold: 0.1,
			expected:      changes{},
		},
		{
			name:          "no-changes-with-kev-and-epss",
			oldDB:         []string{"cve-2020-15415"},
			newDB:         []string{"cve-2020-15415"},
			include:       Includes{Vulns: true, KEV: true, EPSS: true},
			epssThreshold: 0.1,
			expected:      changes{},
		},

		// ── CVE (vulnerability_handles) add/remove/modify ──────────────────
		{
			name:    "vuln-added",
			oldDB:   []string{"cve-2025-24456"},
			newDB:   []string{"cve-2025-24456", "cve-2025-21916"},
			include: Includes{Vulns: true},
			expected: changes{
				added{v("nvd", "CVE-2025-21916")},
			},
		},
		{
			name:    "vuln-removed",
			oldDB:   []string{"cve-2025-24456", "cve-2025-21916"},
			newDB:   []string{"cve-2025-24456"},
			include: Includes{Vulns: true},
			expected: changes{
				removed{v("nvd", "CVE-2025-21916")},
			},
		},
		{
			// uses cve-2025-24456-modified which changes description, lastModified, and severity
			name:    "vuln-modified",
			oldDB:   []string{"cve-2025-21916", "cve-2025-24456"},
			newDB:   []string{"cve-2025-21916", "cve-2025-24456-modified"},
			include: Includes{Vulns: true},
			expected: changes{
				modified{v("nvd", "CVE-2025-24456")},
			},
		},
		{
			name:    "vuln-multiple-added",
			oldDB:   []string{"cve-2025-24456"},
			newDB:   []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			include: Includes{Vulns: true},
			expected: changes{
				added{
					v("nvd", "CVE-2025-21916"),
					v("nvd", "CVE-2010-1724"),
				},
			},
		},
		{
			name:    "vuln-multiple-removed",
			oldDB:   []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB:   []string{"cve-2025-24456"},
			include: Includes{Vulns: true},
			expected: changes{
				removed{
					v("nvd", "CVE-2025-21916"),
					v("nvd", "CVE-2010-1724"),
				},
			},
		},
		{
			name:    "vuln-mixed-add-remove-modify",
			oldDB:   []string{"cve-2025-24456", "cve-2025-21916", "cve-2010-1724"},
			newDB:   []string{"cve-2025-24456-modified", "cve-2025-21916", "cve-2010-1725"},
			include: Includes{Vulns: true},
			expected: changes{
				added{v("nvd", "CVE-2010-1725")},
				modified{v("nvd", "CVE-2025-24456")},
				removed{v("nvd", "CVE-2010-1724")},
			},
		},

		// ── KEV-only diffs (CVEs with only KEV entries, no NVD) ────────────
		{
			name:    "kev-added",
			oldDB:   []string{"cve-2025-24456"},
			newDB:   []string{"cve-2025-24456", "cve-2024-4947"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{kevOrEpss("CVE-2024-4947")},
			},
		},
		{
			name:    "kev-removed",
			oldDB:   []string{"cve-2025-24456", "cve-2024-4947"},
			newDB:   []string{"cve-2025-24456"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{kevOrEpss("CVE-2024-4947")},
			},
		},
		{
			name:    "kev-add-and-remove",
			oldDB:   []string{"cve-2025-24456", "cve-2024-4947"},
			newDB:   []string{"cve-2025-24456", "cve-2025-21335"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{
					kevOrEpss("CVE-2024-4947"),
					kevOrEpss("CVE-2025-21335"),
				},
			},
		},
		{
			name:    "kev-multiple-added",
			oldDB:   []string{"cve-2025-24456"},
			newDB:   []string{"cve-2025-24456", "cve-2024-4947", "cve-2025-21335"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{
					kevOrEpss("CVE-2024-4947"),
					kevOrEpss("CVE-2025-21335"),
				},
			},
		},
		{
			name:     "kev-disabled-no-kev-changes-reported",
			oldDB:    []string{"cve-2025-24456"},
			newDB:    []string{"cve-2025-24456", "cve-2024-4947"},
			include:  Includes{Vulns: true, KEV: false},
			expected: changes{},
		},

		// ── EPSS diffs (CVEs with NVD + EPSS data) ────────────────────────
		{
			name:          "epss-added-with-new-vuln",
			oldDB:         []string{"cve-2025-24456"},
			newDB:         []string{"cve-2025-24456", "cve-2022-38178"},
			include:       Includes{Vulns: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				added{v("nvd", "CVE-2022-38178")},
				modified{kevOrEpss("CVE-2022-38178")},
			},
		},
		{
			name:          "epss-removed-with-removed-vuln",
			oldDB:         []string{"cve-2025-24456", "cve-2022-38178"},
			newDB:         []string{"cve-2025-24456"},
			include:       Includes{Vulns: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				modified{kevOrEpss("CVE-2022-38178")},
				removed{v("nvd", "CVE-2022-38178")},
			},
		},
		{
			name:          "epss-disabled-no-epss-changes-reported",
			oldDB:         []string{"cve-2025-24456"},
			newDB:         []string{"cve-2025-24456", "cve-2022-38178"},
			include:       Includes{Vulns: true, EPSS: false},
			epssThreshold: 0.1,
			expected: changes{
				added{v("nvd", "CVE-2022-38178")},
			},
		},
		{
			name:          "epss-enabled-modified-reported",
			oldDB:         []string{"cve-2025-24456", "cve-2025-0282.json", "cve-2020-15415.json"},
			newDB:         []string{"cve-2025-24456", "2025/cve-2025-0282.json", "cve-2025-0282-modified.json", "2020/cve-2020-15415.json", "cve-2020-15415-modified.json"},
			include:       Includes{Vulns: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				modified{kevOrEpss("cve-2025-0282"), kevOrEpss("cve-2020-15415")},
			},
		},

		// ── Combined KEV + EPSS + CVE changes ─────────────────────────────
		{
			// cve-2020-15415 has NVD + KEV + EPSS entries
			name:          "combined-add-nvd-kev-epss",
			oldDB:         []string{"cve-2025-24456"},
			newDB:         []string{"cve-2025-24456", "cve-2020-15415"},
			include:       Includes{Vulns: true, KEV: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				added{v("nvd", "CVE-2020-15415")},
				modified{kevOrEpss("CVE-2020-15415")},
			},
		},
		{
			// cve-2020-15415 has NVD + KEV + EPSS entries
			name:          "combined-remove-nvd-kev-epss",
			oldDB:         []string{"cve-2025-24456", "cve-2020-15415"},
			newDB:         []string{"cve-2025-24456"},
			include:       Includes{Vulns: true, KEV: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				modified{kevOrEpss("CVE-2020-15415")},
				removed{v("nvd", "CVE-2020-15415")},
			},
		},
		{
			// add cve-2025-0282 (NVD+KEV+EPSS) + cve-2025-21916 (NVD only)
			name:          "combined-multiple-adds-mixed-metadata",
			oldDB:         []string{"cve-2025-24456"},
			newDB:         []string{"cve-2025-24456", "cve-2025-0282", "cve-2025-21916"},
			include:       Includes{Vulns: true, KEV: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				added{
					v("nvd", "CVE-2025-0282"),
					v("nvd", "CVE-2025-21916"),
				},
				modified{kevOrEpss("CVE-2025-0282")},
			},
		},
		{
			// KEV change with no vulnerability_handles change
			name:    "kev-change-no-vuln-change",
			oldDB:   []string{"cve-2020-15415", "cve-2024-4947"},
			newDB:   []string{"cve-2020-15415", "cve-2025-21335"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{
					kevOrEpss("CVE-2024-4947"),
					kevOrEpss("CVE-2025-21335"),
				},
			},
		},
		{
			// modify a vuln's metadata and swap KEV entries simultaneously
			name:    "vuln-modify-with-kev-swap",
			oldDB:   []string{"cve-2025-24456", "cve-2025-21916", "cve-2024-4947"},
			newDB:   []string{"cve-2025-24456-modified", "cve-2025-21916", "cve-2025-21335"},
			include: Includes{Vulns: true, KEV: true},
			expected: changes{
				modified{
					kevOrEpss("CVE-2024-4947"),
					kevOrEpss("CVE-2025-21335"),
					v("nvd", "CVE-2025-24456"),
				},
			},
		},
		{
			// add vuln, remove vuln, add kev, remove epss
			name:          "complex-mixed-vuln-kev-epss",
			oldDB:         []string{"cve-2025-24456", "cve-2010-1724", "cve-2022-38178"},
			newDB:         []string{"cve-2025-24456", "cve-2025-21916", "cve-2024-4947"},
			include:       Includes{Vulns: true, KEV: true, EPSS: true},
			epssThreshold: 0.1,
			expected: changes{
				added{v("nvd", "CVE-2025-21916")},
				modified{
					kevOrEpss("CVE-2022-38178"),
					kevOrEpss("CVE-2024-4947"),
				},
				removed{
					v("nvd", "CVE-2010-1724"),
					v("nvd", "CVE-2022-38178"),
				},
			},
		},
	}

	testdataDir, err := filepath.Abs("testdata")
	require.NoError(t, err)

	inputDir := filepath.Join(testdataDir, "inputs")

	var tmpdir string
	if debug {
		tmpdir = filepath.Join(testdataDir, "cache")
		t.Logf("using persistent testdata cache dir: %s", tmpdir)
	} else {
		tmpdir = t.TempDir()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := filepath.Join(tmpdir, regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(t.Name(), "_"))

			oldDB := filepath.Join(tmpdir, "oldDB")
			err = os.MkdirAll(oldDB, 0o755)
			require.NoError(t, err)

			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 11, 18, 1, 5, 0, time.UTC),
				oldDB,
				inputDir,
				tt.oldDB...)

			newDB := filepath.Join(tmpdir, "newDB")
			testdb.BuildFromFlatFileDir(t,
				time.Date(2022, 8, 12, 1, 55, 19, 0, time.UTC),
				newDB,
				inputDir,
				tt.newDB...)

			epssThreshold := tt.epssThreshold
			if epssThreshold == 0 && tt.include.EPSS {
				epssThreshold = 0.1
			}

			differ, err := NewDBDiffer(Config{
				Config:        installation.Config{},
				Debug:         debug,
				OldDB:         oldDB,
				NewDB:         newDB,
				Include:       tt.include,
				EPSSThreshold: epssThreshold,
			})
			require.NoError(t, err)
			require.NotNil(t, differ)

			result, err := differ.Diff()
			require.NoError(t, err)

			vulnDiff := result.Vulnerabilities
			if len(tt.expected) == 0 {
				if vulnDiff != nil {
					assert.Empty(t, vulnDiff.Added, "expected no added vulns")
					assert.Empty(t, vulnDiff.Modified, "expected no modified vulns")
					assert.Empty(t, vulnDiff.Removed, "expected no removed vulns")
				}
				return
			}

			require.NotNil(t, vulnDiff, "expected vulnerability diff")

			hasAdded := false
			hasModified := false
			hasRemoved := false
			for _, exp := range tt.expected {
				switch exp := exp.(type) {
				case added:
					hasAdded = true
					requireVulnIDs(t, "added", vulnDiff.Added, exp...)
				case modified:
					hasModified = true
					requireVulnIDs(t, "modified", vulnDiff.Modified, exp...)
				case removed:
					hasRemoved = true
					requireVulnIDs(t, "removed", vulnDiff.Removed, exp...)
				}
			}
			if !hasAdded {
				assert.Empty(t, vulnDiff.Added, "expected no added vulns")
			}
			if !hasModified {
				assert.Empty(t, vulnDiff.Modified, "expected no modified vulns")
			}
			if !hasRemoved {
				assert.Empty(t, vulnDiff.Removed, "expected no removed vulns")
			}
		})
	}
}
