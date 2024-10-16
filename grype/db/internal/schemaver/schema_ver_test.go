package schemaver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaVer_VersionComponents(t *testing.T) {
	tests := []struct {
		name             string
		version          SchemaVer
		expectedModel    int
		expectedRevision int
		expectedAddition int
	}{
		{
			name:             "go case",
			version:          "1.2.3",
			expectedModel:    1,
			expectedRevision: 2,
			expectedAddition: 3,
		},
		{
			name:             "model only",
			version:          "1.0.0",
			expectedModel:    1,
			expectedRevision: 0,
			expectedAddition: 0,
		},
		{
			name:             "invalid model",
			version:          "0.2.3",
			expectedModel:    -1,
			expectedRevision: 2,
			expectedAddition: 3,
		},
		{
			name:             "invalid version format",
			version:          "invalid.version",
			expectedModel:    -1,
			expectedRevision: -1,
			expectedAddition: -1,
		},
		{
			name:             "zero version",
			version:          "0.0.0",
			expectedModel:    -1,
			expectedRevision: 0,
			expectedAddition: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			type subject struct {
				name string
				exp  int
				fn   func() (int, bool)
			}

			for _, sub := range []subject{
				{
					name: "model",
					exp:  tt.expectedModel,
					fn:   tt.version.ModelPart,
				},
				{
					name: "revision",
					exp:  tt.expectedRevision,
					fn:   tt.version.RevisionPart,
				},
				{
					name: "addition",
					exp:  tt.expectedAddition,
					fn:   tt.version.AdditionPart,
				},
			} {
				t.Run(sub.name, func(t *testing.T) {
					act, ok := sub.fn()

					if sub.exp == -1 {
						require.False(t, ok, fmt.Sprintf("Expected %s to be invalid", sub.name))
						return
					}
					require.True(t, ok, fmt.Sprintf("Expected %s to be valid", sub.name))
					assert.Equal(t, sub.exp, act, fmt.Sprintf("Expected %s to be %d, got %d", sub.name, sub.exp, act))
				})
			}

		})
	}
}
