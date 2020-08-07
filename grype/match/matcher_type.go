package match

const (
	UnknownMatcherType MatcherType = iota
	ApkMatcher
	RubyBundleMatcher
	DpkgMatcher
	RpmDBMatcher
	JavaMatcher
	PythonMatcher
	JavascriptMatcher
)

var matcherTypeStr = []string{
	"UnknownMatcherType",
	"apk-matcher",
	"ruby-bundle-matcher",
	"dpkg-matcher",
	"rpmdb-matcher",
	"java-matcher",
	"python-matcher",
	"javascript-matcher",
}

var AllMatcherTypes = []MatcherType{
	ApkMatcher,
	RubyBundleMatcher,
	DpkgMatcher,
	RpmDBMatcher,
	JavaMatcher,
	PythonMatcher,
	JavascriptMatcher,
}

type MatcherType int

func (f MatcherType) String() string {
	if int(f) >= len(matcherTypeStr) || f < 0 {
		return matcherTypeStr[0]
	}

	return matcherTypeStr[f]
}
