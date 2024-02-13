package cpe

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/syft/syft/cpe"
)

func TestMatchWithoutVersion(t *testing.T) {
	tests := []struct {
		name       string
		compare    cpe.CPE
		candidates []cpe.CPE
		expected   []cpe.CPE
	}{
		{
			name:    "GoCase",
			compare: cpe.Must("cpe:2.3:*:python-requests:requests:2.3.0:*:*:*:*:python:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*", ""),
			},
		},
		{
			name:    "IgnoreVersion",
			compare: cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*", ""),
			},
		},
		{
			name:    "MatchByTargetSW",
			compare: cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*", ""),
			},
		},
		{
			name:    "MatchByName",
			compare: cpe.Must("cpe:2.3:*:name:name5:3.2:*:*:*:*:java:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name1:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name2:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name3:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name4:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*", ""),
			},
		},
		{
			name:    "MatchByVendor",
			compare: cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*", ""),
			},
		},
		{
			name:    "MatchAnyVendorOrTargetSW",
			compare: cpe.Must("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*", ""),
			candidates: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*", ""),
				cpe.Must("cpe:2.3:*:name5:NOMATCH:3.2:*:*:*:*:*:*:*", ""),
			},
			expected: []cpe.CPE{
				cpe.Must("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*", ""),
				cpe.Must("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*", ""),
				cpe.Must("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*", ""),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := MatchWithoutVersion(test.compare, test.candidates)

			if len(actual) != len(test.expected) {
				for _, e := range actual {
					t.Errorf("   unexpected entry: %+v", e.Attributes.BindToFmtString())
				}
				t.Fatalf("unexpected number of entries: %d", len(actual))
			}

			for idx, a := range actual {
				e := test.expected[idx]
				if a.Attributes.BindToFmtString() != e.Attributes.BindToFmtString() {
					dmp := diffmatchpatch.New()
					diffs := dmp.DiffMain(a.Attributes.BindToFmtString(), e.Attributes.BindToFmtString(), true)
					t.Errorf("mismatched entries @ %d:\n\texpected:%+v\n\t  actual:%+v\n\t    diff:%+v\n", idx, e.Attributes.BindToFmtString(), a.Attributes.BindToFmtString(), dmp.DiffPrettyText(diffs))
				}
			}
		})
	}
}
