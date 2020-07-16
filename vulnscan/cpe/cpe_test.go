package cpe

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/sergi/go-diff/diffmatchpatch"
	"testing"
)

func must(c CPE, e error) CPE {
	if e != nil {
		panic(e)
	}
	return c
}


func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CPE
	}{
		{
			name: "gocase",
			input: `cpe:/a:10web:form_maker:1.0.0::~~~wordpress~~`,
			expected: must(New(`cpe:2.3:a:10web:form_maker:1.0.0:*:*:*:*:wordpress:*:*`)),
		},
		{
			name: "dashes",
			input: `cpe:/a:7-zip:7-zip:4.56:beta:~~~windows~~`,
			expected: must(New(`cpe:2.3:a:7-zip:7-zip:4.56:beta:*:*:*:windows:*:*`)),
		},
		{
			name: "URL escape characters",
			input: `cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~`,
			expected: must(New(`cpe:2.3:a:$0.99_kindle_books_project:$0.99_kindle_books:6:*:*:*:*:android:*:*`)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := New(test.input)
			if err != nil {
				t.Fatalf("got an error while creating CPE: %+v", err)
			}

			if actual.BindToFmtString() != test.expected.BindToFmtString() {
				t.Errorf("mismatched entries:\n\texpected:%+v\n\t  actual:%+v\n", test.expected.BindToFmtString(), actual.BindToFmtString())
			}

		})
	}
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []CPE
	}{
		{
			name: "simple package",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.DebPkg,
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := Generate(&test.p)
			if err != nil {
				t.Fatalf("got an error while generating CPEs: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, e := range actual {
					t.Errorf("   unexpected entry: %+v", e.BindToFmtString())
				}
				t.Fatalf("unexpected number of entries: %d", len(actual))
			}

			for idx, a := range actual {
				e := test.expected[idx]
				if a.BindToFmtString() != e.BindToFmtString() {
					t.Errorf("mismatched entries @ %d:\n\texpected:%+v\n\t  actual:%+v\n", idx, e.BindToFmtString(), a.BindToFmtString())
				}
			}
		})
	}
}

func TestMatchWithoutVersion(t *testing.T) {
	tests := []struct {
		name       string
		compare    CPE
		candidates []CPE
		expected   []CPE
	}{
		{
			name:    "GoCase",
			compare: must(New("cpe:2.3:*:python-requests:requests:2.3.0:*:*:*:*:python:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:a:python-requests:requests:2.2.1:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "IgnoreVersion",
			compare: must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:3.3:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:5.5:*:*:*:*:java:*:*")),
			},
		},
		{
			name:    "MatchByTargetSW",
			compare: must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "MatchByName",
			compare: must(New("cpe:2.3:*:name:name5:3.2:*:*:*:*:java:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:*:name:name1:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name2:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name3:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name4:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name:name5:3.2:*:*:*:*:*:*:*")),
			},
		},
		{
			name:    "MatchByVendor",
			compare: must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
			},
		},
		{
			name:    "MatchAnyVendorOrTargetSW",
			compare: must(New("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
			candidates: []CPE{
				must(New("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
				must(New("cpe:2.3:*:name5:NOMATCH:3.2:*:*:*:*:*:*:*")),
			},
			expected: []CPE{
				must(New("cpe:2.3:*:name1:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:jaba-no-bother:*:*")),
				must(New("cpe:2.3:*:name3:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name4:name:3.2:*:*:*:*:java:*:*")),
				must(New("cpe:2.3:*:name5:name:3.2:*:*:*:*:*:*:*")),
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
