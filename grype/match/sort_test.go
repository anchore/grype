package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestByElements_ComparisonDoesNotMutateMatches pins that comparing two matches leaves both of them as
// they were. Less only reaches the fix-versions comparison when the vulnerability ID, package name,
// version and type all tie, so the fixtures tie on exactly those and differ in namespace (which Less
// does not consult) and in the order their fix versions are listed in.
func TestByElements_ComparisonDoesNotMutateMatches(t *testing.T) {
	pkgID := pkg.ID(uuid.NewString())
	newMatch := func(namespace string, fixVersions []string) Match {
		return Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{ID: "CVE-2020-0001", Namespace: namespace},
				Fix:       vulnerability.Fix{Versions: fixVersions},
			},
			Package: pkg.Package{ID: pkgID, Name: "package-a", Version: "1.0.0", Type: syftPkg.NpmPkg},
			Details: Details{{Type: ExactDirectMatch, Matcher: StockMatcher}},
		}
	}

	t.Run("Less leaves both operands' fix versions in their original order", func(t *testing.T) {
		first := newMatch("nvd:cpe", []string{"2.0.0", "1.0.0"})
		second := newMatch("github:language:javascript", []string{"3.0.0", "1.0.0"})

		ByElements([]Match{first, second}).Less(0, 1)

		assert.Equal(t, []string{"2.0.0", "1.0.0"}, first.Vulnerability.Fix.Versions)
		assert.Equal(t, []string{"3.0.0", "1.0.0"}, second.Vulnerability.Fix.Versions)
	})

	t.Run("Sorted returns matches with their fix versions in their original order", func(t *testing.T) {
		matches := NewMatches(
			newMatch("nvd:cpe", []string{"2.0.0", "1.0.0"}),
			newMatch("github:language:javascript", []string{"3.0.0", "1.0.0"}),
		)

		byNamespace := map[string][]string{}
		for _, m := range matches.Sorted() {
			byNamespace[m.Vulnerability.Namespace] = m.Vulnerability.Fix.Versions
		}

		assert.Equal(t, []string{"2.0.0", "1.0.0"}, byNamespace["nvd:cpe"], "fix versions were reordered by sorting")
		assert.Equal(t, []string{"3.0.0", "1.0.0"}, byNamespace["github:language:javascript"], "fix versions were reordered by sorting")
	})
}
