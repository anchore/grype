package cpe

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestMatchWithoutVersion(t *testing.T) {
	tests := []struct {
		name       string
		compare    pkg.CPE
		candidates []pkg.CPE
		expected   []pkg.CPE
	}{
		{
			name:    "GoCase",
			compare: must(pkg.NewCPE("cpe:2.3:*:python-requests:requests:2.3.0:*:*:*:*:python:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "IgnoreVersion",
			compare: must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*")),
			},
		},
		{
			name:    "MatchByTargetSW",
			compare: must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "MatchByName",
			compare: must(pkg.NewCPE("cpe:2.3:*:name:name5:3.2:*:*:*:*:java:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name1:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name2:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name3:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name4:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "MatchByVendor",
			compare: must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
			},
		},
		{
			name:    "MatchAnyVendorOrTargetSW",
			compare: must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
			candidates: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name5:NOMATCH:3.2:*:*:*:*:*:*:*")),
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := MatchWithoutVersion(test.compare, test.candidates)

			if len(actual) != len(test.expected) {
				for _, e := range actual {
					t.Errorf("   unexpected entry: %+v", e.BindToFmtString())
				}
				t.Fatalf("unexpected number of entries: %d", len(actual))
			}

			for idx, a := range actual {
				e := test.expected[idx]
				if a.BindToFmtString() != e.BindToFmtString() {
					dmp := diffmatchpatch.New()
					diffs := dmp.DiffMain(a.BindToFmtString(), e.BindToFmtString(), true)
					t.Errorf("mismatched entries @ %d:\n\texpected:%+v\n\t  actual:%+v\n\t    diff:%+v\n", idx, e.BindToFmtString(), a.BindToFmtString(), dmp.DiffPrettyText(diffs))
				}
			}
		})
	}
}
