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
	JavascriptMatcher  MatcherType = "javascript-matcher"
	MsrcMatcher        MatcherType = "msrc-matcher"
)

var AllMatcherTypes = []MatcherType{
	ApkMatcher,
	RubyGemMatcher,
	DpkgMatcher,
	RpmDBMatcher,
	JavaMatcher,
	PythonMatcher,
	JavascriptMatcher,
	MsrcMatcher,
}

type MatcherType string
