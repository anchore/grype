package name

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPythonResolver_Normalize(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
	}{
		{
			name: "PyYAML",
			// note we are not lowercasing since the DB is case-insensitive for name columns
			normalized: "PyYAML",
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
			normalized: "AbCd-1234-XyZZZ",
		},
	}

	resolver := PythonResolver{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolvedNames := resolver.Normalize(test.name)
			assert.Equal(t, resolvedNames, test.normalized)
		})
	}
}
