package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/anchore/go-collections"
	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/version"
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

// constraint narrows the generated schema of a single config key
type constraint func(*jsonschema.Schema)

// configConstraints maps a dotted config path to a constraint; "[]" addresses array items (e.g. "ignore[].fix-state").
// Every path must exist in the generated schema, otherwise generation fails.
// Only the documented lower-case spelling of a value is accepted, while grype also accepts other casings and some
// aliases (e.g. "all" for "all-layers"). Left open: from and ignore[].package.type (syft adds values regularly, which
// would force a schema version bump on routine syft updates) and dev.profile (not exported by clio).
var configConstraints = map[string]constraint{
	"log.level":                 optionalEnum(stringsOf(logger.Levels())...),
	"fail-on-severity":          optionalEnum(severityNames()...),
	"sort-by":                   enum(stringsOf(models.SortStrategies())...),
	"search.scope":              enum(stringsOf(source.AllScopes)...),
	"default-image-pull-source": optionalEnum(imagePullSources()...),

	// items are trimmed, and may name a destination file (e.g. "json=report.json")
	"output": list(`\s*`+alternation(formatNames())+`(?:=[^,]+)?\s*`, formatNames()...),
	// items are matched exactly, so no whitespace around commas
	"vex-add": list(alternation(augmentStatuses()), augmentStatuses()...),
	// split on commas without trimming, skipping empty items
	"ignore-wontfix": pattern(commaSeparated(alternation(fixStates()) + "?")),

	"match.dpkg.missing-epoch-strategy": enum(missingEpochStrategies()...),
	"match.rpm.missing-epoch-strategy":  enum(missingEpochStrategies()...),
	"fix-channel.redhat-eus.apply":      optionalEnum(fixChannelModes()...),
	"fix-channel.ubuntu-esm.apply":      optionalEnum(fixChannelModes()...),

	// a typo in a rule field silently stops the rule from matching, rather than failing the scan
	"ignore[].fix-state":  optionalEnum(fixStates()...),
	"ignore[].match-type": optionalEnum(stringsOf([]match.Type{match.ExactDirectMatch, match.ExactIndirectMatch, match.CPEMatch})...),
	"ignore[].vex-status": optionalEnum(stringsOf([]vexStatus.Status{vexStatus.NotAffected, vexStatus.Affected, vexStatus.Fixed, vexStatus.UnderInvestigation})...),
}

func enum(values ...string) constraint {
	return func(s *jsonschema.Schema) {
		s.Enum = append(s.Enum, toAny(values)...)
	}
}

// optionalEnum also accepts "", which grype treats as unset
func optionalEnum(values ...string) constraint {
	return enum(append([]string{""}, values...)...)
}

func pattern(re string) constraint {
	return func(s *jsonschema.Schema) {
		s.Pattern = re
	}
}

// list constrains each item of a list value, given as an array or as a comma-separated string, to the item pattern;
// values are offered for completion
func list(item string, values ...string) constraint {
	return func(s *jsonschema.Schema) {
		array, str := listForms(s)
		array.Items.Pattern = "^(?:" + item + ")$"
		array.Items.Examples = toAny(values)
		str.Pattern = commaSeparated(item)
		str.Examples = toAny(values)
	}
}

// listForms returns the array and the string alternative of a list-or-string value
func listForms(s *jsonschema.Schema) (array, str *jsonschema.Schema) {
	for _, alt := range s.OneOf {
		switch alt.Type {
		case jsonTypeArray:
			array = alt
		case jsonTypeString:
			str = alt
		}
	}
	if array == nil || array.Items == nil || str == nil {
		panic("list constraint applied to a value that is not a list of strings")
	}
	return array, str
}

// commaSeparated matches a comma-separated list of items; an empty string is an empty list
func commaSeparated(item string) string {
	return "^(?:(?:" + item + ")(?:,(?:" + item + "))*)?$"
}

// alternation matches exactly one of values
func alternation(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = regexp.QuoteMeta(v)
	}
	return "(?:" + strings.Join(quoted, "|") + ")"
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func stringsOf[T ~string](values []T) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

func severityNames() []string {
	var out []string
	for _, s := range vulnerability.AllSeverities() {
		out = append(out, s.String())
	}
	return out
}

func formatNames() []string {
	return stringsOf(format.AvailableFormats)
}

func fixStates() []string {
	return stringsOf(vulnerability.AllFixStates())
}

func augmentStatuses() []string {
	return stringsOf(vexStatus.AugmentList())
}

func missingEpochStrategies() []string {
	return stringsOf([]version.MissingEpochStrategy{version.MissingEpochStrategyZero, version.MissingEpochStrategyAuto})
}

func fixChannelModes() []string {
	return stringsOf([]distro.FixChannelEnabled{distro.ChannelNeverEnabled, distro.ChannelAlwaysEnabled, distro.ChannelConditionallyEnabled})
}

// imagePullSources returns the names syft accepts for its default image pull source: the tags of all pull providers
func imagePullSources() []string {
	providers := collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...)
	return providers.Select(sourceproviders.PullTag).Tags()
}

func applyConstraints(root *jsonschema.Schema) {
	for path, c := range configConstraints {
		s := lookupSchema(root, path)
		if s == nil {
			panic(fmt.Sprintf("config constraint path %q does not exist in the schema", path))
		}
		c(s)
	}
}

func lookupSchema(root *jsonschema.Schema, path string) *jsonschema.Schema {
	s := root
	for part := range strings.SplitSeq(path, ".") {
		name, items := strings.CutSuffix(part, "[]")
		if s.Properties == nil {
			return nil
		}
		next, ok := s.Properties.Get(name)
		if !ok {
			return nil
		}
		if items {
			next = arrayItems(next)
			if next == nil {
				return nil
			}
		}
		s = next
	}
	return s
}

// arrayItems returns the item schema of an array, including the array form of a list-or-string value
func arrayItems(s *jsonschema.Schema) *jsonschema.Schema {
	if s.Type == jsonTypeArray {
		return s.Items
	}
	for _, alt := range s.OneOf {
		if alt.Type == jsonTypeArray {
			return alt.Items
		}
	}
	return nil
}
