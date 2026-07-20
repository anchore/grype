package matcher

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/bitnami"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/hex"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/msrc"
	"github.com/anchore/grype/grype/matcher/pacman"
	"github.com/anchore/grype/grype/matcher/portage"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rapidfort"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
)

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Java       java.MatcherConfig
	Ruby       ruby.MatcherConfig
	Python     python.MatcherConfig
	Dotnet     dotnet.MatcherConfig
	Javascript javascript.MatcherConfig
	Golang     golang.MatcherConfig
	Rust       rust.MatcherConfig
	Hex        hex.MatcherConfig
	Stock      stock.MatcherConfig
	Dpkg       dpkg.MatcherConfig
	Rpm        rpm.MatcherConfig
}

func NewDefaultMatchers(mc Config) []match.Matcher {
	return []match.Matcher{
		dpkg.NewDpkgMatcher(mc.Dpkg),
		ruby.NewRubyMatcher(mc.Ruby),
		python.NewPythonMatcher(mc.Python),
		dotnet.NewDotnetMatcher(mc.Dotnet),
		rpm.NewRpmMatcher(mc.Rpm),
		java.NewJavaMatcher(mc.Java),
		javascript.NewJavascriptMatcher(mc.Javascript),
		&apk.Matcher{},
		golang.NewGolangMatcher(mc.Golang),
		&msrc.Matcher{},
		&portage.Matcher{},
		rust.NewRustMatcher(mc.Rust),
		hex.NewHexMatcher(mc.Hex),
		stock.NewStockMatcher(mc.Stock),
		&bitnami.Matcher{},
		&pacman.Matcher{},
	}
}

// ApplySelectionPolicy swaps the default OS matchers (dpkg/apk/rpm) for the
// single RapidFort matcher when the scan target is a RapidFort-curated image.
// The identity signal comes from ctx.IsRapidFortImage, which the package
// provider populated by looking for the marker file on the image (see
// pkg.RapidFortMarkerPath); we intentionally avoid reading it out of the
// source labels here so the decision is content-based, not metadata-based.
func ApplySelectionPolicy(matchers []match.Matcher, ctx pkg.Context) []match.Matcher {
	if !rapidfort.IsRapidFortImage(ctx) {
		return matchers
	}

	rfMatcher := rapidfort.NewMatcher()
	replacements := map[match.MatcherType]match.Matcher{
		match.DpkgMatcher: rfMatcher,
		match.ApkMatcher:  rfMatcher,
		match.RpmMatcher:  rfMatcher,
	}

	return applyMatcherOverrides(matchers, replacements)
}

func applyMatcherOverrides(matchers []match.Matcher, replacements map[match.MatcherType]match.Matcher) []match.Matcher {
	if len(replacements) == 0 {
		return matchers
	}

	var out []match.Matcher
	added := make(map[match.MatcherType]struct{})

	for _, m := range matchers {
		replacement, ok := replacements[m.Type()]
		if !ok {
			out = append(out, m)
			continue
		}

		if _, exists := added[replacement.Type()]; exists {
			continue
		}

		out = append(out, replacement)
		added[replacement.Type()] = struct{}{}
	}

	return out
}
