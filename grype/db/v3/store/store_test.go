package store

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"

	v3 "github.com/anchore/grype/grype/db/v3"
	"github.com/anchore/grype/grype/db/v3/store/model"
)

func assertIDReader(t *testing.T, reader v3.IDReader, expected v3.ID) {
	t.Helper()
	if actual, err := reader.GetID(); err != nil {
		t.Fatalf("failed to get ID: %+v", err)
	} else {
		diffs := deep.Equal(&expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}
}

func TestStore_GetID_SetID(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	expected := v3.ID{
		BuildTimestamp: time.Now().UTC(),
		SchemaVersion:  2,
	}

	if err = s.SetID(expected); err != nil {
		t.Fatalf("failed to set ID: %+v", err)
	}

	assertIDReader(t, s, expected)

}

func assertVulnerabilityReader(t *testing.T, reader v3.VulnerabilityStoreReader, namespace, name string, expected []v3.Vulnerability) {
	if actual, err := reader.GetVulnerability(namespace, name); err != nil {
		t.Fatalf("failed to get Vulnerability: %+v", err)
	} else {
		if len(actual) != len(expected) {
			t.Fatalf("unexpected number of vulns: %d", len(actual))
		}
		for idx := range actual {
			diffs := deep.Equal(expected[idx], actual[idx])
			if len(diffs) > 0 {
				for _, d := range diffs {
					t.Errorf("Diff: %+v", d)
				}
			}
		}
	}
}

func TestStore_GetVulnerability_SetVulnerability(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	extra := []v3.Vulnerability{
		{
			ID:                "my-cve-33333",
			PackageName:       "package-name-2",
			Namespace:         "my-namespace",
			VersionConstraint: "< 1.0",
			VersionFormat:     "semver",
			CPEs:              []string{"a-cool-cpe"},
			RelatedVulnerabilities: []v3.VulnerabilityReference{
				{
					ID:        "another-cve",
					Namespace: "nvd",
				},
				{
					ID:        "an-other-cve",
					Namespace: "nvd",
				},
			},
			Fix: v3.Fix{
				Versions: []string{"2.0.1"},
				State:    v3.FixedState,
			},
		},
		{
			ID:                "my-other-cve-33333",
			PackageName:       "package-name-3",
			Namespace:         "my-namespace",
			VersionConstraint: "< 509.2.2",
			VersionFormat:     "semver",
			CPEs:              []string{"a-cool-cpe"},
			RelatedVulnerabilities: []v3.VulnerabilityReference{
				{
					ID:        "another-cve",
					Namespace: "nvd",
				},
				{
					ID:        "an-other-cve",
					Namespace: "nvd",
				},
			},
			Fix: v3.Fix{
				State: v3.NotFixedState,
			},
		},
	}

	expected := []v3.Vulnerability{
		{
			ID:                "my-cve",
			PackageName:       "package-name",
			Namespace:         "my-namespace",
			VersionConstraint: "< 1.0",
			VersionFormat:     "semver",
			CPEs:              []string{"a-cool-cpe"},
			RelatedVulnerabilities: []v3.VulnerabilityReference{
				{
					ID:        "another-cve",
					Namespace: "nvd",
				},
				{
					ID:        "an-other-cve",
					Namespace: "nvd",
				},
			},
			Fix: v3.Fix{
				Versions: []string{"1.0.1"},
				State:    v3.FixedState,
			},
		},
		{
			ID:                "my-other-cve",
			PackageName:       "package-name",
			Namespace:         "my-namespace",
			VersionConstraint: "< 509.2.2",
			VersionFormat:     "semver",
			CPEs:              []string{"a-cool-cpe"},
			RelatedVulnerabilities: []v3.VulnerabilityReference{
				{
					ID:        "another-cve",
					Namespace: "nvd",
				},
				{
					ID:        "an-other-cve",
					Namespace: "nvd",
				},
			},
			Fix: v3.Fix{
				Versions: []string{"4.0.5"},
				State:    v3.FixedState,
			},
		},
	}

	total := append(expected, extra...)

	if err = s.AddVulnerability(total...); err != nil {
		t.Fatalf("failed to set Vulnerability: %+v", err)
	}

	var allEntries []model.VulnerabilityModel
	s.(*store).db.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

	assertVulnerabilityReader(t, s, expected[0].Namespace, expected[0].PackageName, expected)

}

func assertVulnerabilityMetadataReader(t *testing.T, reader v3.VulnerabilityMetadataStoreReader, id, namespace string, expected v3.VulnerabilityMetadata) {
	if actual, err := reader.GetVulnerabilityMetadata(id, namespace); err != nil {
		t.Fatalf("failed to get metadata: %+v", err)
	} else if actual == nil {
		t.Fatalf("no metadata returned for id=%q namespace=%q", id, namespace)
	} else {
		sortMetadataCvss(actual.Cvss)
		sortMetadataCvss(expected.Cvss)

		// make sure they both have the same number of CVSS entries - preventing a panic on later assertions
		assert.Len(t, expected.Cvss, len(actual.Cvss))
		for idx, actualCvss := range actual.Cvss {
			assert.Equal(t, actualCvss.Vector, expected.Cvss[idx].Vector)
			assert.Equal(t, actualCvss.Version, expected.Cvss[idx].Version)
			assert.Equal(t, actualCvss.Metrics, expected.Cvss[idx].Metrics)

			actualVendor, err := json.Marshal(actualCvss.VendorMetadata)
			if err != nil {
				t.Errorf("unable to marshal vendor metadata: %q", err)
			}
			expectedVendor, err := json.Marshal(expected.Cvss[idx].VendorMetadata)
			if err != nil {
				t.Errorf("unable to marshal vendor metadata: %q", err)
			}
			assert.Equal(t, string(actualVendor), string(expectedVendor))

		}

		// nil the Cvss field because it is an interface - verification of Cvss
		// has already happened at this point
		expected.Cvss = nil
		actual.Cvss = nil
		assert.Equal(t, &expected, actual)
	}

}

func sortMetadataCvss(cvss []v3.Cvss) {
	sort.Slice(cvss, func(i, j int) bool {
		// first, sort by Vector
		if cvss[i].Vector > cvss[j].Vector {
			return true
		}
		if cvss[i].Vector < cvss[j].Vector {
			return false
		}
		// then try to sort by BaseScore if Vector is the same
		return cvss[i].Metrics.BaseScore < cvss[j].Metrics.BaseScore
	})
}

// CustomMetadata is effectively a noop, its values aren't meaningful and are
// mostly useful to ensure that any type can be stored and then retrieved for
// assertion in these test cases where custom vendor CVSS scores are used
type CustomMetadata struct {
	SuperScore string
	Vendor     string
}

func TestStore_GetVulnerabilityMetadata_SetVulnerabilityMetadata(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	total := []v3.VulnerabilityMetadata{
		{
			ID:           "my-cve",
			RecordSource: "record-source",
			Namespace:    "namespace",
			Severity:     "pretty bad",
			URLs:         []string{"https://ancho.re"},
			Description:  "best description ever",
			Cvss: []v3.Cvss{
				{
					VendorMetadata: CustomMetadata{
						Vendor:     "redhat",
						SuperScore: "1000",
					},
					Version: "2.0",
					Metrics: v3.NewCvssMetrics(
						1.1,
						2.2,
						3.3,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--NOT",
				},
				{
					Version: "3.0",
					Metrics: v3.NewCvssMetrics(
						1.3,
						2.1,
						3.2,
					),
					Vector:         "AV:N/AC:L/Au:N/C:P/I:P/A:P--NICE",
					VendorMetadata: nil,
				},
			},
		},
		{
			ID:           "my-other-cve",
			RecordSource: "record-source",
			Namespace:    "namespace",
			Severity:     "pretty bad",
			URLs:         []string{"https://ancho.re"},
			Description:  "worst description ever",
			Cvss: []v3.Cvss{
				{
					Version: "2.0",
					Metrics: v3.NewCvssMetrics(
						4.1,
						5.2,
						6.3,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
				},
				{
					Version: "3.0",
					Metrics: v3.NewCvssMetrics(
						1.4,
						2.5,
						3.6,
					),
					Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
				},
			},
		},
	}

	if err = s.AddVulnerabilityMetadata(total...); err != nil {
		t.Fatalf("failed to set metadata: %+v", err)
	}

	var allEntries []model.VulnerabilityMetadataModel
	s.(*store).db.Find(&allEntries)
	if len(allEntries) != len(total) {
		t.Fatalf("unexpected number of entries: %d", len(allEntries))
	}

}

func TestStore_MergeVulnerabilityMetadata(t *testing.T) {
	tests := []struct {
		name     string
		add      []v3.VulnerabilityMetadata
		expected v3.VulnerabilityMetadata
		err      bool
	}{
		{
			name: "go-case",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []v3.Cvss{
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "merge-links",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://google.com"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://yahoo.com"},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re", "https://google.com", "https://yahoo.com"},
				Cvss:         []v3.Cvss{},
			},
		},
		{
			name: "bad-severity",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "meh, push that for next tuesday...",
					URLs:         []string{"https://redhat.com"},
				},
			},
			err: true,
		},
		{
			name: "mismatch-description",
			err:  true,
			add: []v3.VulnerabilityMetadata{
				{

					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
		},
		{
			name: "mismatch-cvss2",
			err:  false,
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "best description ever",
				Cvss: []v3.Cvss{
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:P--VERY",
					},
				},
			},
		},
		{
			name: "mismatch-cvss3",
			err:  false,
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "best description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								0,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "best description ever",
				Cvss: []v3.Cvss{
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							0,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempDir, err := ioutil.TempDir("", "grype-db-test-store")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.RemoveAll(dbTempDir)

			s, err := New(dbTempDir, true)
			if err != nil {
				t.Fatalf("could not create store: %+v", err)
			}

			// add each metadata in order
			var theErr error
			for _, metadata := range test.add {
				err = s.AddVulnerabilityMetadata(metadata)
				if err != nil {
					theErr = err
					break
				}
			}

			if test.err && theErr == nil {
				t.Fatalf("expected error but did not get one")
			} else if !test.err && theErr != nil {
				t.Fatalf("expected no error but got one: %+v", theErr)
			} else if test.err && theErr != nil {
				// test pass...
				return
			}

			// ensure there is exactly one entry
			var allEntries []model.VulnerabilityMetadataModel
			s.(*store).db.Find(&allEntries)
			if len(allEntries) != 1 {
				t.Fatalf("unexpected number of entries: %d", len(allEntries))
			}

			// get the resulting metadata object
			if actual, err := s.GetVulnerabilityMetadata(test.expected.ID, test.expected.Namespace); err != nil {
				t.Fatalf("failed to get metadata: %+v", err)
			} else {
				diffs := deep.Equal(&test.expected, actual)
				if len(diffs) > 0 {
					for _, d := range diffs {
						t.Errorf("Diff: %+v", d)
					}
				}
			}
		})
	}
}

func TestCvssScoresInMetadata(t *testing.T) {
	tests := []struct {
		name     string
		add      []v3.VulnerabilityMetadata
		expected v3.VulnerabilityMetadata
	}{
		{
			name: "append-cvss",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []v3.Cvss{
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
		{
			name: "append-vendor-cvss",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "2.0",
							Metrics: v3.NewCvssMetrics(
								4.1,
								5.2,
								6.3,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
							VendorMetadata: CustomMetadata{
								SuperScore: "100",
								Vendor:     "debian",
							},
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []v3.Cvss{
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
					},
					{
						Version: "2.0",
						Metrics: v3.NewCvssMetrics(
							4.1,
							5.2,
							6.3,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--VERY",
						VendorMetadata: CustomMetadata{
							SuperScore: "100",
							Vendor:     "debian",
						},
					},
				},
			},
		},
		{
			name: "avoids-duplicate-cvss",
			add: []v3.VulnerabilityMetadata{
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
				{
					ID:           "my-cve",
					RecordSource: "record-source",
					Namespace:    "namespace",
					Severity:     "pretty bad",
					URLs:         []string{"https://ancho.re"},
					Description:  "worst description ever",
					Cvss: []v3.Cvss{
						{
							Version: "3.0",
							Metrics: v3.NewCvssMetrics(
								1.4,
								2.5,
								3.6,
							),
							Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
						},
					},
				},
			},
			expected: v3.VulnerabilityMetadata{
				ID:           "my-cve",
				RecordSource: "record-source",
				Namespace:    "namespace",
				Severity:     "pretty bad",
				URLs:         []string{"https://ancho.re"},
				Description:  "worst description ever",
				Cvss: []v3.Cvss{
					{
						Version: "3.0",
						Metrics: v3.NewCvssMetrics(
							1.4,
							2.5,
							3.6,
						),
						Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P--GOOD",
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbTempDir, err := ioutil.TempDir("", "grype-db-test-s")
			if err != nil {
				t.Fatalf("could not create temp file: %+v", err)
			}
			defer os.RemoveAll(dbTempDir)

			s, err := New(dbTempDir, true)
			if err != nil {
				t.Fatalf("could not create s: %+v", err)
			}

			// add each metadata in order
			for _, metadata := range test.add {
				err = s.AddVulnerabilityMetadata(metadata)
				if err != nil {
					t.Fatalf("unable to s vulnerability metadata: %+v", err)
				}
			}

			// ensure there is exactly one entry
			var allEntries []model.VulnerabilityMetadataModel
			s.(*store).db.Find(&allEntries)
			if len(allEntries) != 1 {
				t.Fatalf("unexpected number of entries: %d", len(allEntries))
			}

			assertVulnerabilityMetadataReader(t, s, test.expected.ID, test.expected.Namespace, test.expected)
		})
	}
}

func Test_DiffStore(t *testing.T) {
	//GIVEN
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s1, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}
	dbTempFile, err = ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s2, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	baseVulns := []v3.Vulnerability{
		{
			Namespace:         "github:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "npm",
			ID:                "CVE-123-7654",
			PackageName:       "npm:axios",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:npm:axios:*:*:*:*:*:*"},
			Fix: v3.Fix{
				State: v3.UnknownFixState,
			},
		},
		{
			Namespace:         "nuget",
			ID:                "GHSA-****-******",
			PackageName:       "nuget:net",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:nuget:net:*:*:*:*:*:*"},
			Fix: v3.Fix{
				State: v3.UnknownFixState,
			},
		},
		{
			Namespace:         "hex",
			ID:                "GHSA-^^^^-^^^^^^",
			PackageName:       "hex:esbuild",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:hex:esbuild:*:*:*:*:*:*"},
		},
	}
	baseMetadata := []v3.VulnerabilityMetadata{
		{
			Namespace:  "nuget",
			ID:         "GHSA-****-******",
			DataSource: "nvd",
		},
	}
	targetVulns := []v3.Vulnerability{
		{
			Namespace:         "github:python",
			ID:                "CVE-123-4567",
			PackageName:       "pypi:requests",
			VersionConstraint: "< 2.0 >= 1.29",
			CPEs:              []string{"cpe:2.3:pypi:requests:*:*:*:*:*:*"},
		},
		{
			Namespace:         "github:go",
			ID:                "GHSA-....-....",
			PackageName:       "hashicorp:nomad",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:golang:hashicorp:nomad:*:*:*:*:*"},
		},
		{
			Namespace:         "github:go",
			ID:                "GHSA-....-....",
			PackageName:       "hashicorp:n",
			VersionConstraint: "< 2.0 >= 1.17",
			CPEs:              []string{"cpe:2.3:golang:hashicorp:n:*:*:*:*:*"},
		},
		{
			Namespace:         "npm",
			ID:                "CVE-123-7654",
			PackageName:       "npm:axios",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:npm:axios:*:*:*:*:*:*"},
			Fix: v3.Fix{
				State: v3.WontFixState,
			},
		},
		{
			Namespace:         "nuget",
			ID:                "GHSA-****-******",
			PackageName:       "nuget:net",
			VersionConstraint: "< 3.0 >= 2.17",
			CPEs:              []string{"cpe:2.3:nuget:net:*:*:*:*:*:*"},
			Fix: v3.Fix{
				State: v3.UnknownFixState,
			},
		},
	}
	expectedDiffs := []v3.Diff{
		{
			Reason:    v3.DiffChanged,
			ID:        "CVE-123-4567",
			Namespace: "github:python",
			Packages:  []string{"pypi:requests"},
		},
		{
			Reason:    v3.DiffChanged,
			ID:        "CVE-123-7654",
			Namespace: "npm",
			Packages:  []string{"npm:axios"},
		},
		{
			Reason:    v3.DiffRemoved,
			ID:        "GHSA-****-******",
			Namespace: "nuget",
			Packages:  []string{"nuget:net"},
		},
		{
			Reason:    v3.DiffAdded,
			ID:        "GHSA-....-....",
			Namespace: "github:go",
			Packages:  []string{"hashicorp:nomad", "hashicorp:n"},
		},
		{
			Reason:    v3.DiffRemoved,
			ID:        "GHSA-^^^^-^^^^^^",
			Namespace: "hex",
			Packages:  []string{"hex:esbuild"},
		},
	}

	for _, vuln := range baseVulns {
		s1.AddVulnerability(vuln)
	}
	for _, vuln := range targetVulns {
		s2.AddVulnerability(vuln)
	}
	for _, meta := range baseMetadata {
		s1.AddVulnerabilityMetadata(meta)
	}

	//WHEN
	result, err := s1.DiffStore(s2)

	//THEN
	sort.SliceStable(*result, func(i, j int) bool {
		return (*result)[i].ID < (*result)[j].ID
	})

	assert.NoError(t, err)
	assert.Equal(t, expectedDiffs, *result)
}
