package v6

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/discard"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

// loggedEntry is a trace message logged with fields, each formatted as the logger would.
type loggedEntry struct {
	msg    string
	fields map[string]string
}

// debugRecorder records the trace messages logged with fields, and discards the rest.
type debugRecorder struct {
	logger.Logger
	entries *[]loggedEntry
}

func (r debugRecorder) WithFields(fields ...any) logger.MessageLogger {
	return fieldsRecorder{MessageLogger: r.Logger, fields: fields, entries: r.entries}
}

type fieldsRecorder struct {
	logger.MessageLogger
	fields  []any
	entries *[]loggedEntry
}

func (r fieldsRecorder) Trace(args ...any) {
	e := loggedEntry{msg: fmt.Sprint(args...), fields: map[string]string{}}
	for i := 0; i+1 < len(r.fields); i += 2 {
		e.fields[fmt.Sprint(r.fields[i])] = fmt.Sprint(r.fields[i+1])
	}
	*r.entries = append(*r.entries, e)
}

// recordDebugLogs records what is logged at trace level with fields until the test ends.
func recordDebugLogs(t *testing.T) *[]loggedEntry {
	t.Helper()
	var entries []loggedEntry
	prev := log.Get()
	log.Set(debugRecorder{Logger: discard.New(), entries: &entries})
	t.Cleanup(func() { log.Set(prev) })
	return &entries
}

func TestSearchIndex_Rewrite_LogsRuledSearches(t *testing.T) { //nolint:funlen // one case per rule action
	rh := *distro.New(distro.RapidFortRedHat, "9", "")
	p := searchOf("curl", "1.0-1.rf", rh)
	const (
		curl   = "curl@1.0-1.rf in rapidfort-redhat:9"
		curlRF = "curl@1.0-1.rf in rapidfort-redhat:9+rf"
	)
	replaceRF := SearchRule{Action: SearchRuleReplace, MatchDistroName: "rapidfort-redhat", MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf"), Priority: 30}
	addRF := SearchRule{Action: SearchRuleAdd, MatchDistroName: "rapidfort-redhat", MatchPackageName: "curl", ReplacementChannel: ptr("rf")}
	addY := SearchRule{Action: SearchRuleAdd, MatchDistroName: "rapidfort-redhat", MatchPackageName: "curl", ReplacementChannel: ptr("y")}
	drop := SearchRule{Action: SearchRuleDrop, MatchDistroName: "rapidfort-redhat", MatchPackageName: "curl"}

	tests := []struct {
		name   string
		rules  []SearchRule
		search []vulnerability.Criteria
		want   []loggedEntry
	}{
		{
			name:   "no rule applies",
			rules:  []SearchRule{replaceRF},
			search: nameSearch(searchOf("curl", "1.0-1", rh)),
		},
		{
			name:   "replaced",
			rules:  []SearchRule{replaceRF},
			search: nameSearch(p),
			want: []loggedEntry{
				{msg: "search rule replaced search", fields: map[string]string{"search": curl, "new": curlRF, "rule": replaceRF.String()}},
			},
		},
		{
			name:   "added",
			rules:  []SearchRule{addRF},
			search: nameSearch(p),
			want: []loggedEntry{
				{msg: "search rule added search", fields: map[string]string{"search": curl, "new": curlRF, "rule": addRF.String()}},
			},
		},
		{
			name:   "dropped",
			rules:  []SearchRule{drop},
			search: nameSearch(p),
			want: []loggedEntry{
				{msg: "search rule dropped search", fields: map[string]string{"search": curl, "rule": drop.String()}},
			},
		},
		{
			name:   "a replace rule's search beside a kept search is added",
			rules:  []SearchRule{replaceRF, addY},
			search: nameSearch(p),
			want: []loggedEntry{
				{msg: "search rule added search", fields: map[string]string{"search": curl, "new": curlRF, "rule": replaceRF.String()}},
				{msg: "search rule added search", fields: map[string]string{"search": curl, "new": "curl@1.0-1.rf in rapidfort-redhat:9+y", "rule": addY.String()}},
			},
		},
		{
			name:   "dropped, beside another rule's search",
			rules:  []SearchRule{drop, {Action: SearchRuleAdd, MatchDistroName: "rapidfort-redhat", MatchPackageName: "curl", ReplacementDistroName: ptr("rapidfort-redhat"), Priority: 5}},
			search: nameSearch(p),
			want: []loggedEntry{
				{msg: "search rule dropped search", fields: map[string]string{"search": curl, "rule": drop.String()}},
				{msg: "search rule added search", fields: map[string]string{"search": curl, "new": curl, "rule": "add match_distro_name=rapidfort-redhat match_package_name=curl replacement_distro_name=rapidfort-redhat priority=5"}},
			},
		},
		{
			name:   "an upstream CPE search",
			rules:  []SearchRule{{Action: SearchRuleReplace, MatchCPEProduct: "curl", ReplacementCPEVendor: "haxx"}},
			search: []vulnerability.Criteria{search.ByCPE(cpe.Must("cpe:2.3:a:vendor:curl:1.0:*:*:*:*:*:*:*", "")), search.BySourcePackage(), search.WithPackage(p)},
			want: []loggedEntry{
				{msg: "search rule replaced search", fields: map[string]string{
					"search": "cpe:2.3:a:vendor:curl:1.0:*:*:*:*:*:*:* in no OS (upstream)",
					"new":    "cpe:2.3:a:haxx:curl:1.0:*:*:*:*:*:*:* in no OS (upstream)",
					"rule":   "replace match_cpe_product=curl replacement_cpe_vendor=haxx",
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := rulesProvider(tt.rules...)
			logged := recordDebugLogs(t)
			rewrites(vp, pkg.Package{}, tt.search)
			assert.Equal(t, tt.want, *logged)
		})
	}
}

func TestSearchRule_String(t *testing.T) {
	tests := []struct {
		row  SearchRule
		want string
	}{
		{
			row:  SearchRule{Action: SearchRuleReplace, MatchDistroName: "rapidfort-redhat", MatchEcosystem: "rpm", MatchPackageVersion: `.*\.rf`, ReplacementChannel: ptr("rf"), Priority: 30},
			want: `replace match_distro_name=rapidfort-redhat match_ecosystem=rpm match_package_version=.*\.rf replacement_channel=rf priority=30`,
		},
		{
			// an empty, non-NULL replacement is a value (here, the rows of no OS)
			row:  SearchRule{Action: SearchRuleAdd, MatchDistroName: "debian", MatchPackageName: "curl", MatchUpstreamSearch: ptr(false), ReplacementDistroName: ptr(""), Priority: -5},
			want: `add match_distro_name=debian match_package_name=curl match_upstream_search=false replacement_distro_name="" priority=-5`,
		},
		{
			row:  SearchRule{Action: SearchRuleReplace, MatchDistroName: "alpine", MatchEcosystem: "apk", ReplacementDistroVersion: ptr(""), ReplacementDistroLabelVersion: ptr("edge")},
			want: `replace match_distro_name=alpine match_ecosystem=apk replacement_distro_version="" replacement_distro_label_version=edge`,
		},
		{
			row:  SearchRule{Action: SearchRuleDrop, MatchCPEVendor: "apache", ExcludeCPEProduct: "log4j", ApplicableClientDBSchemas: ">= 6.1.0"},
			want: `drop match_cpe_vendor=apache exclude_cpe_product=log4j applicable_client_db_schemas=>= 6.1.0`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.row.String())
		})
	}
}
