package cpe

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFromString(t *testing.T) {
	successTests := []struct {
		namespaceString string
		result          *Namespace
	}{
		{
			namespaceString: "abc.xyz:cpe",
			result:          NewNamespace("abc.xyz"),
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
			errorMessage:    "unable to create CPE namespace from empty string",
		},
		{
			namespaceString: "single-component",
			errorMessage:    "unable to create CPE namespace from single-component: incorrect number of components",
		},
		{
			namespaceString: "too:many:components",
			errorMessage:    "unable to create CPE namespace from too:many:components: incorrect number of components",
		},
		{
			namespaceString: "wrong:namespace_type",
			errorMessage:    "unable to create CPE namespace from wrong:namespace_type: type namespace_type is incorrect",
		},
	}

	for _, test := range errorTests {
		_, err := FromString(test.namespaceString)
		assert.EqualError(t, err, test.errorMessage)
	}
}
