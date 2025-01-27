package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isUnknownTarget(t *testing.T) {
	tests := []struct {
		name     string
		targetSW string
		expected bool
	}{
		{name: "supported syft language", targetSW: "python", expected: false},
		{name: "supported non-syft language CPE component", targetSW: "joomla", expected: false},
		{name: "unknown component", targetSW: "abc", expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u := isUnknownTarget(test.targetSW)
			assert.Equal(t, test.expected, u)
		})
	}
}
