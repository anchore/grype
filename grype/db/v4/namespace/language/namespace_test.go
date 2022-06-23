package language

import (
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFromString(t *testing.T) {
	successTests := []struct {
		namespaceString string
		result          *Namespace
	}{
		{
			namespaceString: "github:language:python",
			result:          NewNamespace("github", syftPkg.Python, ""),
		},
		{
			namespaceString: "abc.xyz:language:something",
			result:          NewNamespace("abc.xyz", syftPkg.Language("something"), ""),
		},
		{
			namespaceString: "abc.xyz:language:something:another-package-manager",
			result:          NewNamespace("abc.xyz", syftPkg.Language("something"), syftPkg.Type("another-package-manager")),
		},
	}

	for _, test := range successTests {
		result, _ := FromString(test.namespaceString)
		assert.Equal(t, result, test.result)
	}

	errorTests := []struct {
		namespaceString string
		errorMessage    string
	}{
		{
			namespaceString: "",
			errorMessage:    "unable to create language namespace from empty string",
		},
		{
			namespaceString: "single-component",
			errorMessage:    "unable to create language namespace from single-component: incorrect number of components",
		},
		{
			namespaceString: "two:components",
			errorMessage:    "unable to create language namespace from two:components: incorrect number of components",
		},
		{
			namespaceString: "too:many:components:a:b",
			errorMessage:    "unable to create language namespace from too:many:components:a:b: incorrect number of components",
		},
		{
			namespaceString: "wrong:namespace_type:a:b",
			errorMessage:    "unable to create language namespace from wrong:namespace_type:a:b: type namespace_type is incorrect",
		},
	}

	for _, test := range errorTests {
		_, err := FromString(test.namespaceString)
		assert.EqualError(t, err, test.errorMessage)
	}
}
