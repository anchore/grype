package rapidfort

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
)

func TestIsRapidFortImage(t *testing.T) {
	tests := []struct {
		name     string
		ctx      pkg.Context
		expected bool
	}{
		{
			name:     "zero-value context returns false",
			ctx:      pkg.Context{},
			expected: false,
		},
		{
			name:     "context flag false returns false",
			ctx:      pkg.Context{IsRapidFortImage: false},
			expected: false,
		},
		{
			name:     "context flag true returns true",
			ctx:      pkg.Context{IsRapidFortImage: true},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsRapidFortImage(test.ctx))
		})
	}
}
