package match

const (
	UnknownMatcherType MatcherType = iota
	StockMatcher
	ApkMatcher
	RubyGemMatcher
	DpkgMatcher
	RpmDBMatcher
	JavaMatcher
	PythonMatcher
	JavascriptMatcher
	MsrcMatcher
)

var matcherTypeStr = []string{
	"UnknownMatcherType",
	"stock-matcher",
	"apk-matcher",
	"ruby-gem-matcher",
	"dpkg-matcher",
	"rpmdb-matcher",
	"java-matcher",
	"python-matcher",
	"javascript-matcher",
	"msrc-matcher",
}

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

type MatcherType int

func (f MatcherType) String() string {
	if int(f) >= len(matcherTypeStr) || f < 0 {
		return matcherTypeStr[0]
	}

	return matcherTypeStr[f]
}
