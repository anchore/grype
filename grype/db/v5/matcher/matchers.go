package matcher

import (
	"github.com/anchore/grype/grype/db/v5/matcher/apk"
	"github.com/anchore/grype/grype/db/v5/matcher/dotnet"
	"github.com/anchore/grype/grype/db/v5/matcher/dpkg"
	"github.com/anchore/grype/grype/db/v5/matcher/golang"
	"github.com/anchore/grype/grype/db/v5/matcher/java"
	"github.com/anchore/grype/grype/db/v5/matcher/javascript"
	"github.com/anchore/grype/grype/db/v5/matcher/msrc"
	"github.com/anchore/grype/grype/db/v5/matcher/portage"
	"github.com/anchore/grype/grype/db/v5/matcher/python"
	"github.com/anchore/grype/grype/db/v5/matcher/rpm"
	"github.com/anchore/grype/grype/db/v5/matcher/ruby"
	"github.com/anchore/grype/grype/db/v5/matcher/rust"
	"github.com/anchore/grype/grype/db/v5/matcher/stock"
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
	Stock      stock.MatcherConfig
}

func NewDefaultMatchers(mc Config) []Matcher {
	return []Matcher{
		&dpkg.Matcher{},
		ruby.NewRubyMatcher(mc.Ruby),
		python.NewPythonMatcher(mc.Python),
		dotnet.NewDotnetMatcher(mc.Dotnet),
		&rpm.Matcher{},
		java.NewJavaMatcher(mc.Java),
		javascript.NewJavascriptMatcher(mc.Javascript),
		&apk.Matcher{},
		golang.NewGolangMatcher(mc.Golang),
		&msrc.Matcher{},
		&portage.Matcher{},
		rust.NewRustMatcher(mc.Rust),
		stock.NewStockMatcher(mc.Stock),
	}
}
