package v6

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSearchRule_Validate(t *testing.T) { //nolint:funlen // one case per validation rule
	tests := []struct {
		name    string
		row     SearchRule
		wantErr string
	}{
		{
			name:    "no pattern at all",
			row:     SearchRule{ReplacementDistroName: ptr("echo")},
			wantErr: "must have an exact (non-regex) package name, distro name or ecosystem",
		},
		{
			name:    "replacement package name without a name pattern",
			row:     SearchRule{MatchEcosystem: "rpm", ReplacementPackageName: "x", MatchPackageVersion: `.*\.rf.*`},
			wantErr: "must have a package name pattern",
		},
		{
			name:    "channel substitution without a distro name",
			row:     SearchRule{MatchEcosystem: "rpm", MatchPackageVersion: `.*\.rf.*`, ReplacementChannel: ptr("rf")},
			wantErr: "must have an exact distro name",
		},
		{
			name:    "only regex patterns cannot be indexed",
			row:     SearchRule{MatchPackageName: `rf-.*`, MatchPackageVersion: `.*\.rf.*`, ReplacementPackageName: "${package_name}"},
			wantErr: "must have an exact (non-regex) package name, distro name or ecosystem",
		},
		{
			name:    "a channel substitution with a regex distro name",
			row:     SearchRule{MatchDistroName: `rapidfort-.*`, MatchEcosystem: "rpm", ReplacementChannel: ptr("rf")},
			wantErr: "must have an exact distro name",
		},
		{
			name: "an escaped pattern is exact, and so indexable",
			row:  SearchRule{MatchPackageName: `libstdc\+\+`, ReplacementPackageName: "gcc"},
		},
		{
			name: "an exact pattern's value is its field",
			row:  SearchRule{MatchPackageName: "busybox", ReplacementPackageName: "rf-${package_name}"},
		},
		{
			name:    "positional references are not supported",
			row:     SearchRule{MatchPackageName: "busybox", ReplacementPackageName: "$0"},
			wantErr: "use a named group",
		},
		{
			name: "a regex distro name",
			row:  SearchRule{MatchDistroName: `rapidfort-(?P<base>.*)`, MatchEcosystem: "deb", ReplacementDistroName: ptr("${base}")},
		},
		{
			name:    "no replacement",
			row:     SearchRule{MatchDistroName: "rapidfort-alpine", MatchEcosystem: "apk"},
			wantErr: "must have a replacement",
		},
		{
			name:    "substitution without an ecosystem or package pattern",
			row:     SearchRule{MatchDistroName: "debian", ReplacementChannel: ptr("rf")},
			wantErr: "must match an ecosystem, package name or package version",
		},
		{
			name:    "a channel of no OS",
			row:     SearchRule{MatchDistroName: "debian", MatchEcosystem: "deb", ReplacementDistroName: ptr(""), ReplacementChannel: ptr("rf")},
			wantErr: "cannot have a channel substitution",
		},
		{
			name:    "invalid pattern",
			row:     SearchRule{MatchDistroName: "debian", MatchPackageVersion: `(`, ReplacementChannel: ptr("rf")},
			wantErr: "invalid pattern",
		},
		{
			name:    "a reference to a group no pattern names",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(?P<release>\d+)`, ReplacementChannel: ptr("fc${fedora}")},
			wantErr: "names no group",
		},
		{
			// Go's template rules: `$vx` is the group named "vx", not group "v" then "x"
			name:    "an unbraced reference runs to the end of the name",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(?P<v>\d+)`, ReplacementChannel: ptr("$vx")},
			wantErr: "names no group",
		},
		{
			name:    "an exclude pattern's groups are not referenceable",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `.*`, ExcludePackageVersion: `.*\.(?P<tag>el)\d+`, ReplacementChannel: ptr("${tag}")},
			wantErr: "names no group",
		},
		{
			name:    "a group named by two patterns is ambiguous",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `(?P<x>.*)`, MatchPackageVersion: `(?P<x>.*)`, ReplacementChannel: ptr("${x}")},
			wantErr: "more than one pattern",
		},
		{
			name:    "a group may not shadow a field",
			row:     SearchRule{MatchDistroName: "d", MatchPackageName: `(?P<package_name>.*)-rf`, ReplacementPackageName: "${package_name}"},
			wantErr: "shadows the field",
		},
		{
			name:    "a field the rule does not match is not referenceable",
			row:     SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("${package_name}")},
			wantErr: "names no group",
		},
		{
			name: "a matched field is referenceable",
			row:  SearchRule{MatchDistroName: "d", MatchEcosystem: "rpm", ReplacementDistroName: ptr("rf-${distro_name}-${ecosystem}")},
		},
		{
			name: "a name repeated across alternation branches of one pattern",
			row:  SearchRule{MatchDistroName: "d", MatchPackageVersion: `.*\.fc(?P<v>\d+)|.*\.f(?P<v>\d+)`, ReplacementChannel: ptr("fc${v}")},
		},
		{
			name: "named references resolve across patterns",
			row:  SearchRule{MatchDistroName: "d", MatchDistroVersion: `(?P<major>\d+).*`, MatchPackageName: `(?P<base>.*)-rf`, ReplacementChannel: ptr("el${major}"), ReplacementPackageName: "${base}"},
		},
		{
			name: "a named distro name reference",
			row:  SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*\+(?P<vendor>echo)\d*`, ReplacementDistroName: ptr("${vendor}")},
		},
		{
			name: "an ecosystem is enough to scope a substitution (rapidfort-alpine shape)",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", MatchEcosystem: "apk", ReplacementDistroName: ptr("rapidfort-alpine")},
		},
		{
			name: "a rule may search no OS",
			row:  SearchRule{MatchDistroName: "rapidfort-alpine", MatchEcosystem: "apk", ReplacementDistroName: ptr("")},
		},
		{
			name: "distro name substitution without a distro pattern is legal (echo shape)",
			row:  SearchRule{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.row.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestParseTemplate(t *testing.T) {
	named := map[string]string{"name": "N", "ax": "A-X", "a": "A"}
	tests := []struct {
		template string
		want     string
	}{
		{template: "", want: ""},
		{template: "rf", want: "rf"},
		{template: "fc$a", want: "fcA"},
		{template: "${a}x", want: "Ax"},
		{template: "$ax", want: "A-X"},
		{template: "$name-$a", want: "N-A"},
		{template: "${name}s", want: "Ns"},
		{template: "$$a", want: "$a"},
		{template: "a$", want: "a$"},
		{template: "a$-b", want: "a$-b"},
		{template: "${name", want: "${name"},
		{template: "${missing}", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			assert.Equal(t, tt.want, parseTemplate(tt.template).expand(func(n string) string { return named[n] }))
		})
	}
}

// requireAllValid fails when a fixture rule would be skipped.
func requireAllValid(t *testing.T, rows []SearchRule) {
	t.Helper()
	for _, r := range rows {
		require.NoError(t, r.Validate())
	}
}

func TestKnownSearchRules_AllValid(t *testing.T) {
	requireAllValid(t, KnownSearchRules())
}

// searchOf states the package a search is for: a name, a version, its OS and/or ecosystem.
func searchOf(name, ver string, where ...any) pkg.Package {
	p := pkg.Package{Name: name, Version: ver}
	for _, w := range where {
		switch w := w.(type) {
		case distro.Distro:
			p.Distro = &w
		case syftPkg.Type:
			p.Type = w
		case syftPkg.Language:
			p.Language = w
		}
	}
	return p
}

// nameSearch is a search by p's name: in p's OS, else in its ecosystem.
func nameSearch(p pkg.Package) []vulnerability.Criteria {
	cs := []vulnerability.Criteria{search.ByPackageName(p.Name)}
	if p.Distro != nil {
		cs = append(cs, search.ByDistro(*p.Distro))
	} else {
		cs = append(cs, search.ByEcosystem(p.Language, p.Type))
	}
	return append(cs, search.WithPackage(p))
}

// cpeSearch is a search by a CPE for p, which reads the rows of no OS.
func cpeSearch(p pkg.Package) []vulnerability.Criteria {
	return []vulnerability.Criteria{search.ByCPE(cpe.Must("cpe:2.3:a:vendor:"+p.Name+":*:*:*:*:*:*:*:*", "")), search.WithPackage(p)}
}

// searched describes one search a rewrite returns.
type searched struct {
	// OS is name@version+channels, empty for the rows of no OS
	OS string
	// Name is the searched name, "cpe" for a CPE search
	Name     string
	Ruled    bool
	Priority int
}

func own(os, name string) searched {
	return searched{OS: os, Name: name}
}

func ruled(os, name string, priority int) searched {
	return searched{OS: os, Name: name, Ruled: true, Priority: priority}
}

func searchesOf(searches [][]vulnerability.Criteria) []searched {
	var out []searched
	for _, set := range searches {
		var s searched
		for _, c := range set {
			switch c := c.(type) {
			case *search.DistroCriteria:
				d := c.Distros[0]
				s.OS = d.Name() + "@" + d.Version + "+" + strings.Join(d.Channels, ",")
			case *search.PackageNameCriteria:
				s.Name = c.PackageName
			case *search.CPECriteria:
				s.Name = "cpe"
			case *search.RuleCriteria:
				s.Ruled, s.Priority = true, c.Priority
			}
		}
		out = append(out, s)
	}
	return out
}

// rewrites returns the searches to run in place of cs, which is cs itself when no rule applies.
func rewrites(vp vulnerabilityProvider, p pkg.Package, cs []vulnerability.Criteria) [][]vulnerability.Criteria {
	searches, rewritten := vp.SearchRewrites(p, cs)
	if !rewritten {
		return [][]vulnerability.Criteria{cs}
	}
	return searches
}

func notRewritten(t *testing.T, vp vulnerabilityProvider, cs []vulnerability.Criteria) {
	t.Helper()
	searches, rewritten := vp.SearchRewrites(pkg.Package{}, cs)
	assert.False(t, rewritten)
	assert.Nil(t, searches)
}

// rulesProvider panics on an invalid rule, which the index would otherwise skip with only a warning.
func rulesProvider(rows ...SearchRule) vulnerabilityProvider {
	for _, r := range rows {
		if err := r.Validate(); err != nil {
			panic(fmt.Sprintf("invalid fixture rule %+v: %v", r, err))
		}
	}
	return vulnerabilityProvider{searchRules: newSearchIndex(rows)}
}

func TestVulnerabilityProvider_SearchRewrites_KnownRules(t *testing.T) { //nolint:funlen // one case per built-in rule
	vp := rulesProvider(KnownSearchRules()...)
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9", "")
	rfUbuntu := *distro.New(distro.RapidFortUbuntu, "22.04", "")
	rfDebian := *distro.New(distro.RapidFortDebian, "12", "")
	rfAlpine := *distro.New(distro.RapidFortAlpine, "3.18", "")
	debian := *distro.New(distro.Debian, "12", "")
	apk, deb, rpm := syftPkg.ApkPkg, syftPkg.DebPkg, syftPkg.RpmPkg

	const (
		rh  = "rapidfort-redhat@9+"
		ubu = "rapidfort-ubuntu@22.04+"
	)

	tests := []struct {
		name   string
		search []vulnerability.Criteria
		want   []searched
	}{
		{
			name:   "rapidfort-redhat rf rebuild marker",
			search: nameSearch(searchOf("curl", "7.76.1-29.el9.rf.1", rfRedhat, rpm)),
			want:   []searched{own(rh, "curl"), ruled(rh+"rf", "curl", 30)},
		},
		{
			name:   "rapidfort-redhat fedora dist tag binds the first tag",
			search: nameSearch(searchOf("curl", "7.78.0-3.fc31.fc43", rfRedhat, rpm)),
			want:   []searched{own(rh, "curl"), ruled(rh+"fc31", "curl", 20)},
		},
		{
			name:   "the rebuild marker and the dist tag both apply, ranked",
			search: nameSearch(searchOf("curl", "7.78.0-3.fc43.rf.1", rfRedhat, rpm)),
			want:   []searched{own(rh, "curl"), ruled(rh+"rf", "curl", 30), ruled(rh+"fc43", "curl", 20)},
		},
		{
			name:   "rf- name fallback",
			search: nameSearch(searchOf("rf-scanner", "1.0-1", rfRedhat, rpm)),
			want:   []searched{own(rh, "rf-scanner"), ruled(rh+"rf", "rf-scanner", 10)},
		},
		{
			name:   "rf- name with a native el version is channel-less",
			search: nameSearch(searchOf("rf-scanner", "1.0-1.el9", rfRedhat, rpm)),
			want:   []searched{own(rh, "rf-scanner")},
		},
		{
			name:   "rf- name with a dist tag ranks the dist tag first",
			search: nameSearch(searchOf("rf-scanner", "1.0-1.fc43", rfRedhat, rpm)),
			want:   []searched{own(rh, "rf-scanner"), ruled(rh+"fc43", "rf-scanner", 20), ruled(rh+"rf", "rf-scanner", 10)},
		},
		{
			name:   "native el version",
			search: nameSearch(searchOf("curl", "7.76.1-29.el9", rfRedhat, rpm)),
			want:   []searched{own(rh, "curl")},
		},
		{
			name:   "rapidfort-redhat rules speak only for rpm packages",
			search: nameSearch(searchOf("curl", "7.76.1-29.el9.rf.1", rfRedhat, syftPkg.PythonPkg)),
			want:   []searched{own(rh, "curl")},
		},
		{
			name:   "rapidfort-ubuntu rebuild",
			search: nameSearch(searchOf("curl", "7.81.0-1ubuntu1.15rfubu1", rfUbuntu, deb)),
			want:   []searched{own(ubu, "curl"), ruled(ubu+"rf", "curl", 30)},
		},
		{
			name:   "rapidfort-ubuntu pre-release rebuild marker",
			search: nameSearch(searchOf("curl", "7.81.0-1rfubuntu1.15~rf.1", rfUbuntu, deb)),
			want:   []searched{own(ubu, "curl"), ruled(ubu+"rf", "curl", 30)},
		},
		{
			name:   "rapidfort-debian rebuild",
			search: nameSearch(searchOf("curl", "7.88.1-10+rf.1", rfDebian, deb)),
			want:   []searched{own("rapidfort-debian@12+", "curl"), ruled("rapidfort-debian@12+rf", "curl", 30)},
		},
		{
			name:   "rapidfort-debian stock build",
			search: nameSearch(searchOf("curl", "7.88.1-10+deb12u5", rfDebian, deb)),
			want:   []searched{own("rapidfort-debian@12+", "curl")},
		},
		{
			name:   "rapidfort-ubuntu stock build",
			search: nameSearch(searchOf("rf-curl", "7.81.0-1ubuntu1.15", rfUbuntu, deb)),
			want:   []searched{own(ubu, "rf-curl")},
		},
		{
			name:   "rapidfort-alpine name search: the redirect names the searched OS, a no-op",
			search: nameSearch(searchOf("curl", "8.5.0-r0", rfAlpine, apk)),
			want:   []searched{own("rapidfort-alpine@3.18+", "curl")},
		},
		{
			name:   "rapidfort-alpine CPE search reads rapidfort-alpine rows in place of NVD",
			search: cpeSearch(searchOf("curl", "8.5.0-r0", rfAlpine, apk)),
			want:   []searched{ruled("rapidfort-alpine@3.18+", "cpe", 0)},
		},
		{
			name:   "rapidfort-alpine rule speaks only for apk packages",
			search: cpeSearch(searchOf("curl", "8.5.0-r0", rfAlpine, syftPkg.NpmPkg)),
			want:   []searched{own("", "cpe")},
		},
		{
			name:   "stock alpine CPE search reads NVD",
			search: cpeSearch(searchOf("curl", "8.5.0-r0", *distro.New(distro.Alpine, "3.18", ""), apk)),
			want:   []searched{own("", "cpe")},
		},
		{
			name:   "rapidfort-redhat rebuild CPE search reads the rf channel in place of NVD",
			search: cpeSearch(searchOf("curl", "7.76.1-29.el9.rf.1", rfRedhat, rpm)),
			want:   []searched{ruled(rh+"rf", "cpe", 30)},
		},
		{
			name:   "echo marker on debian",
			search: nameSearch(searchOf("curl", "7.88.1-10+deb12u5.echo1", debian, deb)),
			want:   []searched{own("debian@12+", "curl"), ruled("echo@12+", "curl", 0)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.want, searchesOf(rewrites(vp, pkg.Package{}, tt.search)))
		})
	}
}

// One case per replacement a rule can make, each reached by the searched package alone.
func TestVulnerabilityProvider_SearchRewrites_Replacements(t *testing.T) { //nolint:funlen // one case per replacement type
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9.4", "")
	deb := *distro.New(distro.Debian, "12", "")
	deb.Channels = []string{"x"}
	debEco := syftPkg.DebPkg

	const (
		rh    = "rapidfort-redhat@9.4+"
		debX  = "debian@12+x"
		debNo = "debian@12+"
	)

	tests := []struct {
		name   string
		rules  []SearchRule
		search []vulnerability.Criteria
		want   []searched
	}{
		{
			name:   "channel: literal, the searched OS version kept",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf")}},
			search: nameSearch(searchOf("curl", "1.0-1.rf", rfRedhat)),
			want:   []searched{own(rh, "curl"), ruled(rh+"rf", "curl", 0)},
		},
		{
			name:   "channel: the first match of a lazy named group",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*?\.fc(?P<v>\d+).*`, ReplacementChannel: ptr("fc${v}")}},
			search: nameSearch(searchOf("curl", "1.0-1.fc31.fc43", rfRedhat)),
			want:   []searched{own(rh, "curl"), ruled(rh+"fc31", "curl", 0)},
		},
		{
			name:   "channel: named group of the distro version pattern",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchDistroVersion: `(?P<major>\d+)(?:\..*)?`, MatchPackageName: `rf-.*`, ReplacementChannel: ptr("el${major}")}},
			search: nameSearch(searchOf("rf-curl", "1.0-1", rfRedhat)),
			want:   []searched{own(rh, "rf-curl"), ruled(rh+"el9", "rf-curl", 0)},
		},
		{
			name:   "channel: named group of the name pattern",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchPackageName: `(?P<stream>rf|fips)-.*`, ReplacementChannel: ptr("${stream}")}},
			search: nameSearch(searchOf("fips-openssl", "3.0-1", rfRedhat)),
			want:   []searched{own(rh, "fips-openssl"), ruled(rh+"fips", "fips-openssl", 0)},
		},
		{
			name:   "channel: an empty expansion selects the channel-less rows",
			rules:  []SearchRule{{MatchDistroName: "debian", MatchPackageVersion: `.*?(?:\+(?P<ch>rf))?`, ReplacementChannel: ptr("${ch}")}},
			search: nameSearch(searchOf("curl", "1.0-1", deb)),
			want:   []searched{own(debX, "curl"), ruled(debNo, "curl", 0)},
		},
		{
			name:   "package name: a field the index matched",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchPackageName: "curl", ReplacementPackageName: "rf-${package_name}"}},
			search: nameSearch(searchOf("curl", "1.0-1", rfRedhat)),
			want:   []searched{own(rh, "curl"), ruled(rh, "rf-curl", 0)},
		},
		{
			name:   "channel: a field matched by a regex",
			rules:  []SearchRule{{MatchDistroName: "rapidfort-redhat", MatchDistroVersion: `9\..*`, MatchPackageName: `rf-.*`, ReplacementChannel: ptr("el${distro_version}")}},
			search: nameSearch(searchOf("rf-curl", "1.0-1", rfRedhat)),
			want:   []searched{own(rh, "rf-curl"), ruled(rh+"el9.4", "rf-curl", 0)},
		},
		{
			name:   "distro name: literal, on an OS search; the OS version kept, channels dropped",
			rules:  []SearchRule{{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")}},
			search: nameSearch(searchOf("curl", "7.88.1-10+deb12u5.echo1", deb, debEco)),
			want:   []searched{own(debX, "curl"), ruled("echo@12+", "curl", 0)},
		},
		{
			name:   "distro name: literal, on an ecosystem search, which it adds to",
			rules:  []SearchRule{{MatchEcosystem: "deb", MatchPackageVersion: `.*[.-]echo.*`, ReplacementDistroName: ptr("echo")}},
			search: nameSearch(searchOf("curl", "7.88.1-10+deb12u5.echo1", debEco)),
			want:   []searched{own("", "curl"), ruled("echo@+", "curl", 0)},
		},
		{
			name:   "distro name: named group",
			rules:  []SearchRule{{MatchEcosystem: "deb", MatchPackageVersion: `.*[.+-](?P<vendor>echo|minimus)\d*`, ReplacementDistroName: ptr("${vendor}")}},
			search: nameSearch(searchOf("curl", "7.88.1-10+deb12u5.echo1", deb, debEco)),
			want:   []searched{own(debX, "curl"), ruled("echo@12+", "curl", 0)},
		},
		{
			name:   "distro name and channel together",
			rules:  []SearchRule{{MatchDistroName: "debian", MatchPackageVersion: `.*\+(?P<vendor>echo)(?P<n>\d+)`, ReplacementDistroName: ptr("${vendor}"), ReplacementChannel: ptr("v${n}")}},
			search: nameSearch(searchOf("curl", "1.0-1+echo2", deb)),
			want:   []searched{own(debX, "curl"), ruled("echo@12+v2", "curl", 0)},
		},
		{
			name:   "no OS: a name search of the rows of no OS",
			rules:  []SearchRule{{MatchDistroName: "debian", MatchPackageName: `curl`, ReplacementDistroName: ptr("")}},
			search: nameSearch(searchOf("curl", "1.0-1", deb)),
			want:   []searched{own(debX, "curl"), ruled("", "curl", 0)},
		},
		{
			name:   "no OS: on a CPE search, which already reads no OS, a no-op",
			rules:  []SearchRule{{MatchDistroName: "debian", MatchEcosystem: "deb", ReplacementDistroName: ptr("")}},
			search: cpeSearch(searchOf("curl", "1.0-1", deb, debEco)),
			want:   []searched{own("", "cpe")},
		},
		{
			name: "no OS: puts NVD back, ranked, when a rule redirects a CPE search",
			rules: []SearchRule{
				{MatchDistroName: "debian", MatchPackageVersion: `.*\+rf.*`, ReplacementChannel: ptr("rf"), Priority: 30},
				{MatchDistroName: "debian", MatchEcosystem: "deb", ReplacementDistroName: ptr(""), Priority: 5},
			},
			search: cpeSearch(searchOf("curl", "1.0-1+rf1", deb, debEco)),
			want:   []searched{ruled(debNo+"rf", "cpe", 30), ruled("", "cpe", 5)},
		},
		{
			name:   "package name: named group of a regex name pattern",
			rules:  []SearchRule{{MatchDistroName: "debian", MatchPackageName: `rf-(?P<base>.+)`, ReplacementPackageName: "${base}"}},
			search: nameSearch(searchOf("rf-curl", "1.0-1", deb)),
			want:   []searched{own(debX, "rf-curl"), ruled(debX, "curl", 0)},
		},
		{
			name:   "package name: named group, on an ecosystem search (rootio shape)",
			rules:  []SearchRule{{MatchEcosystem: "python", MatchPackageName: `rootio[-_](?P<upstream>.+)`, ReplacementPackageName: "${upstream}"}},
			search: nameSearch(searchOf("rootio-requests", "2.31.0", syftPkg.PythonPkg)),
			want:   []searched{own("", "rootio-requests"), ruled("", "requests", 0)},
		},
		{
			name:   "package name: named group of the version pattern",
			rules:  []SearchRule{{MatchEcosystem: "java-archive", MatchPackageName: `.*`, MatchPackageVersion: `.*\.(?P<flavor>jre\d+)`, ReplacementPackageName: "${package_name}-${flavor}"}},
			search: nameSearch(searchOf("guava", "32.1.3.jre8", syftPkg.JavaPkg)),
			want:   []searched{own("", "guava"), ruled("", "guava-jre8", 0)},
		},
		{
			name:   "package name: not applied to a CPE search, which has no name",
			rules:  []SearchRule{{MatchEcosystem: "python", MatchPackageName: `rootio[-_](?P<upstream>.+)`, ReplacementPackageName: "${upstream}"}},
			search: cpeSearch(searchOf("rootio-requests", "2.31.0", syftPkg.PythonPkg)),
			want:   []searched{own("", "cpe")},
		},
		{
			name: "package name: the searched name and repeats are not added",
			rules: []SearchRule{
				{MatchDistroName: "debian", MatchPackageName: `(?P<head>cu)rl`, ReplacementPackageName: "rf-${head}"},
				{MatchDistroName: "debian", MatchPackageName: `cu(?P<rest>rl)`, ReplacementPackageName: "cu${rest}"},
				{MatchDistroName: "debian", MatchPackageName: `(?P<n>curl)`, ReplacementPackageName: "rf-cu"},
			},
			search: nameSearch(searchOf("curl", "1.0-1", deb)),
			want:   []searched{own(debX, "curl"), ruled(debX, "rf-cu", 0)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := rulesProvider(tt.rules...)
			assert.ElementsMatch(t, tt.want, searchesOf(rewrites(vp, pkg.Package{}, tt.search)))
		})
	}
}

func TestVulnerabilityProvider_SearchRewrites_Package(t *testing.T) { //nolint:funlen // one case per package shape
	rfRedhat := *distro.New(distro.RapidFortRedHat, "9", "")
	const rh = "rapidfort-redhat@9+"
	vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf")})

	t.Run("no rule applies: cs is searched as is", func(t *testing.T) {
		cs := nameSearch(searchOf("curl", "1.0-1", rfRedhat))
		notRewritten(t, vp, cs)
	})

	t.Run("a pattern on a value the search does not state does not match", func(t *testing.T) {
		for _, cs := range [][]vulnerability.Criteria{
			nameSearch(searchOf("curl", "", rfRedhat)),
			nameSearch(searchOf("", "1.0-1.rf", rfRedhat)),
			nameSearch(searchOf("curl", "1.0-1.rf")),
		} {
			notRewritten(t, vp, cs)
		}
	})

	t.Run("an ecosystem search reads no OS, whatever OS the package was found on", func(t *testing.T) {
		p := searchOf("curl", "1.0-1.rf", rfRedhat)
		cs := []vulnerability.Criteria{search.ByPackageName("curl"), search.ByEcosystem("", syftPkg.RpmPkg), search.WithPackage(p)}
		notRewritten(t, vp, cs)
	})

	t.Run("the package falls back to the one given when the search states none", func(t *testing.T) {
		p := searchOf("curl", "1.0-1.rf", rfRedhat)
		cs := []vulnerability.Criteria{search.ByPackageName("curl"), search.ByDistro(rfRedhat)}
		assert.ElementsMatch(t, []searched{own(rh, "curl"), ruled(rh+"rf", "curl", 0)}, searchesOf(rewrites(vp, p, cs)))
	})

	t.Run("the ecosystem falls back to the language", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchEcosystem: "python", MatchPackageName: `rootio-(?P<upstream>.+)`, ReplacementPackageName: "${upstream}"})
		got := searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("rootio-requests", "", syftPkg.Python))))
		assert.ElementsMatch(t, []searched{own("", "rootio-requests"), ruled("", "requests", 0)}, got)
	})

	t.Run("exclude patterns reject only a present subject", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `rf-.*`, ExcludePackageName: `rf-skip`, ExcludePackageVersion: `.*\.el\d+`, ReplacementChannel: ptr("rf")})
		assert.Len(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("rf-curl", "1.0-1", rfRedhat)))), 2)
		assert.Len(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("rf-curl", "", rfRedhat)))), 2, "no version to exclude")
		assert.Len(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("rf-curl", "1.0-1.el9", rfRedhat)))), 1)
		assert.Len(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("rf-skip", "1.0-1", rfRedhat)))), 1)
	})

	t.Run("the distro version matches the release, then the label", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "ubuntu", MatchDistroVersion: `(?P<code>jammy)`, MatchPackageName: `.*`, ReplacementChannel: ptr("${code}-rf")})
		ubuntu := *distro.New(distro.Ubuntu, "22.04", "jammy")
		got := searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", ubuntu))))
		assert.Contains(t, got, ruled("ubuntu@22.04+jammy-rf", "curl", 0))
	})

	t.Run("a match type reference resolves to the value that matched", func(t *testing.T) {
		vp := rulesProvider(SearchRule{MatchDistroName: "ubuntu", MatchDistroVersion: `jammy|22\.04`, MatchPackageName: `.*`, ReplacementChannel: ptr("${distro_version}-rf")})
		jammy := *distro.New(distro.Ubuntu, "22.04", "jammy")
		assert.Contains(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", jammy)))), ruled("ubuntu@22.04+22.04-rf", "curl", 0), "the release, tried first")
		vp = rulesProvider(SearchRule{MatchDistroName: "ubuntu", MatchDistroVersion: `jammy`, MatchPackageName: `.*`, ReplacementChannel: ptr("${distro_version}-rf")})
		assert.Contains(t, searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", jammy)))), ruled("ubuntu@22.04+jammy-rf", "curl", 0), "the label, when only it matched")
	})

	t.Run("every matching rule applies, at its priority", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 2},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("b"), Priority: 1},
		)
		got := searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", rfRedhat))))
		assert.ElementsMatch(t, []searched{own(rh, "curl"), ruled(rh+"a", "curl", 2), ruled(rh+"b", "curl", 1)}, got)
	})

	t.Run("a rule's OS and name are one search", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `(?P<head>cu)rl`, ReplacementChannel: ptr("a"), ReplacementPackageName: "rf-${head}", Priority: 2},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("c"), Priority: 1},
		)
		got := searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", rfRedhat))))
		assert.ElementsMatch(t, []searched{own(rh, "curl"), ruled(rh+"a", "rf-cu", 2), ruled(rh+"c", "curl", 1)}, got)
	})

	t.Run("rules searching the same rows keep the higher priority", func(t *testing.T) {
		vp := rulesProvider(
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `curl`, ReplacementChannel: ptr("a"), Priority: 1},
			SearchRule{MatchDistroName: "rapidfort-redhat", MatchPackageName: `cu.*`, ReplacementChannel: ptr("a"), Priority: 3},
		)
		got := searchesOf(rewrites(vp, pkg.Package{}, nameSearch(searchOf("curl", "", rfRedhat))))
		assert.ElementsMatch(t, []searched{own(rh, "curl"), ruled(rh+"a", "curl", 3)}, got)
	})
}

func TestVulnerabilityProvider_SearchRewrites_KeepsSourcePackage(t *testing.T) {
	deb := *distro.New(distro.Debian, "12", "")
	vp := rulesProvider(SearchRule{MatchDistroName: "debian", MatchPackageName: `rf-(?P<base>.+)`, ReplacementPackageName: "${base}"})
	cs := []vulnerability.Criteria{search.ByPackageName("rf-curl"), search.BySourcePackage(), search.ByDistro(deb), search.WithPackage(searchOf("rf-curl", "1.0", deb))}

	var names []string
	for _, set := range rewrites(vp, pkg.Package{}, cs) {
		for _, c := range set {
			if nc, ok := c.(*search.PackageNameCriteria); ok {
				names = append(names, nc.PackageName)
			}
		}
		assert.Contains(t, set, search.BySourcePackage(), "every search is still for a source package")
	}
	assert.ElementsMatch(t, []string{"rf-curl", "curl"}, names)
}

func TestFilterSearchRulesForClient(t *testing.T) {
	clientVersion := version.New("6.1.0", version.SemanticFormat)
	rows := []SearchRule{
		{MatchDistroName: "a", MatchPackageName: "x", ReplacementChannel: ptr("c")},
		{MatchDistroName: "b", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "< 6.0.0"},
		{MatchDistroName: "c", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: ">= 6.0.0"},
		// an unparsable constraint fails open
		{MatchDistroName: "d", MatchPackageName: "x", ReplacementChannel: ptr("c"), ApplicableClientDBSchemas: "not-a-constraint"},
	}

	got := filterSearchRulesForClient(rows, clientVersion)
	var names []string
	for _, r := range got {
		names = append(names, r.MatchDistroName)
	}
	assert.Equal(t, []string{"a", "c", "d"}, names)
}
