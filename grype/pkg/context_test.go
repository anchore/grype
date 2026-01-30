package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
)

func TestContext_DistroDetectionFailed(t *testing.T) {
	tests := []struct {
		name     string
		ctx      Context
		expected bool
	}{
		{
			name:     "detection failed is false by default",
			ctx:      Context{},
			expected: false,
		},
		{
			name: "detection failed is true when set",
			ctx: Context{
				DistroDetectionFailed: true,
			},
			expected: true,
		},
		{
			name: "detection failed with distro present",
			ctx: Context{
				Distro:                distro.New(distro.Ubuntu, "22.04", "jammy"),
				DistroDetectionFailed: false,
			},
			expected: false,
		},
		{
			name: "detection failed with nil distro",
			ctx: Context{
				Distro:                nil,
				DistroDetectionFailed: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ctx.DistroDetectionFailed)
		})
	}
}
