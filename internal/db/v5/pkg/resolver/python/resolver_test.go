package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolver_Normalize(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
	}{
		{
			name:       "PyYAML",
			normalized: "pyyaml",
		},
		{
			name:       "oslo.concurrency",
			normalized: "oslo-concurrency",
		},
		{
			name:       "",
			normalized: "",
		},
		{
			name:       "test---1",
			normalized: "test-1",
		},
		{
			name:       "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalized: "abcd-1234-xyzzz",
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvedNames := resolver.Normalize(test.name)
			assert.Equal(t, resolvedNames, test.normalized)
		})
	}
}
