package stock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResolver_Normalize(t *testing.T) {
	tests := []struct {
		packageName string
		normalized  string
	}{
		{
			packageName: "PyYAML",
			normalized:  "pyyaml",
		},
		{
			packageName: "oslo.concurrency",
			normalized:  "oslo.concurrency",
		},
		{
			packageName: "",
			normalized:  "",
		},
		{
			packageName: "test---1",
			normalized:  "test---1",
		},
		{
			packageName: "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalized:  "abcd.-__.--.-___.__.--1234____----....xyzzz",
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		resolvedNames := resolver.Normalize(test.packageName)
		assert.Equal(t, resolvedNames, test.normalized)
	}
}
