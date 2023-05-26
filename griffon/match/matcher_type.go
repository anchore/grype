package match

const (
	UnknownMatcherType MatcherType = "UnknownMatcherType"
	StockMatcher       MatcherType = "stock-matcher"
	ApkMatcher         MatcherType = "apk-matcher"
	RubyGemMatcher     MatcherType = "ruby-gem-matcher"
	DpkgMatcher        MatcherType = "dpkg-matcher"
	RpmMatcher         MatcherType = "rpm-matcher"
	JavaMatcher        MatcherType = "java-matcher"
	PythonMatcher      MatcherType = "python-matcher"
	DotnetMatcher      MatcherType = "dotnet-matcher"
	JavascriptMatcher  MatcherType = "javascript-matcher"
	MsrcMatcher        MatcherType = "msrc-matcher"
	PortageMatcher     MatcherType = "portage-matcher"
	GoModuleMatcher    MatcherType = "go-module-matcher"
)

var AllMatcherTypes = []MatcherType{
	ApkMatcher,
	RubyGemMatcher,
	DpkgMatcher,
	RpmMatcher,
	JavaMatcher,
	PythonMatcher,
	DotnetMatcher,
	JavascriptMatcher,
	MsrcMatcher,
	PortageMatcher,
	GoModuleMatcher,
}

type MatcherType string
