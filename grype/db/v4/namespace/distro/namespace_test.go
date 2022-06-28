package distro

import (
	"testing"

	"github.com/stretchr/testify/assert"

	grypeDistro "github.com/anchore/grype/grype/distro"
)

func TestFromString(t *testing.T) {
	successTests := []struct {
		namespaceString string
		result          *Namespace
	}{
		{
			namespaceString: "alpine:distro:alpine:3.15",
			result:          NewNamespace("alpine", grypeDistro.Alpine, "3.15"),
		},
		{
			namespaceString: "redhat:distro:redhat:8",
			result:          NewNamespace("redhat", grypeDistro.RedHat, "8"),
		},
		{
			namespaceString: "abc.xyz:distro:unknown:abcd~~~",
			result:          NewNamespace("abc.xyz", grypeDistro.Type("unknown"), "abcd~~~"),
		},
		{
			namespaceString: "msrc:distro:windows:10111",
			result:          NewNamespace("msrc", grypeDistro.Type("windows"), "10111"),
		},
		{
			namespaceString: "amazon:distro:amazonlinux:2022",
			result:          NewNamespace("amazon", grypeDistro.AmazonLinux, "2022"),
		},
		{
			namespaceString: "amazon:distro:amazonlinux:2",
			result:          NewNamespace("amazon", grypeDistro.AmazonLinux, "2"),
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
			errorMessage:    "unable to create distro namespace from empty string",
		},
		{
			namespaceString: "single-component",
			errorMessage:    "unable to create distro namespace from single-component: incorrect number of components",
		},
		{
			namespaceString: "two:components",
			errorMessage:    "unable to create distro namespace from two:components: incorrect number of components",
		},
		{
			namespaceString: "still:not:enough",
			errorMessage:    "unable to create distro namespace from still:not:enough: incorrect number of components",
		},
		{
			namespaceString: "too:many:components:a:b",
			errorMessage:    "unable to create distro namespace from too:many:components:a:b: incorrect number of components",
		},
		{
			namespaceString: "wrong:namespace_type:a:b",
			errorMessage:    "unable to create distro namespace from wrong:namespace_type:a:b: type namespace_type is incorrect",
		},
	}

	for _, test := range errorTests {
		_, err := FromString(test.namespaceString)
		assert.EqualError(t, err, test.errorMessage)
	}
}
