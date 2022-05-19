package match

const (
	UnknownMatcherType MatcherType = "UnknownMatcherType"
	StockMatcher       MatcherType = "stock-matcher"
	ApkMatcher         MatcherType = "apk-matcher"
	RubyGemMatcher     MatcherType = "ruby-gem-matcher"
	DpkgMatcher        MatcherType = "dpkg-matcher"
	RpmDBMatcher       MatcherType = "rpmdb-matcher"
	JavaMatcher        MatcherType = "java-matcher"
	PythonMatcher      MatcherType = "python-matcher"
	DotnetMatcher      MatcherType = "dotnet-matcher"
	JavascriptMatcher  MatcherType = "javascript-matcher"
	MsrcMatcher        MatcherType = "msrc-matcher"
	PortageMatcher     MatcherType = "portage-matcher"
)

var AllMatcherTypes = []MatcherType{
	ApkMatcher,
	RubyGemMatcher,
	DpkgMatcher,
	RpmDBMatcher,
	JavaMatcher,
	PythonMatcher,
	DotnetMatcher,
	JavascriptMatcher,
	MsrcMatcher,
	PortageMatcher,
}

type MatcherType string
