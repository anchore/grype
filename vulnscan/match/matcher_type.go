package match

const (
	UnknownMatcherType MatcherType = iota
	RubyBundleMatcher
	DpkgMatcher
	RpmDBMatcher
	JavaMatcher
	PythonMatcher
)

var matcherTypeStr = []string{
	"UnknownMatcherType",
	"ruby-bundle-matcher",
	"dpkg-matcher",
	"rpmdb-matcher",
	"java-matcher",
	"python-matcher",
}

var AllMatcherTypes = []MatcherType{
	RubyBundleMatcher,
	DpkgMatcher,
	RpmDBMatcher,
	JavaMatcher,
	PythonMatcher,
}

type MatcherType int

func (f MatcherType) String() string {
	if int(f) >= len(matcherTypeStr) || f < 0 {
		return matcherTypeStr[0]
	}

	return matcherTypeStr[f]
}
