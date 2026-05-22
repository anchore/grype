package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCPEParts(t *testing.T) {
	tests := []struct {
		name    string
		parts   []string
		wantErr bool
	}{
		{name: "all valid", parts: []string{"a", "h", "o"}, wantErr: false},
		{name: "subset valid", parts: []string{"a"}, wantErr: false},
		{name: "empty rejected", parts: nil, wantErr: true},
		{name: "empty slice rejected", parts: []string{}, wantErr: true},
		{name: "invalid part rejected", parts: []string{"a", "x"}, wantErr: true},
		{name: "uppercase not accepted", parts: []string{"A"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCPEParts(tt.parts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateRequestedProviders(t *testing.T) {
	tests := []struct {
		name      string
		onDisk    []string
		requested []string
		want      []string
		wantErr   bool
	}{
		{
			name:      "no filter returns all on-disk",
			onDisk:    []string{"alpine", "alma", "rhel"},
			requested: nil,
			want:      []string{"alpine", "alma", "rhel"},
		},
		{
			name:      "filter intersects with on-disk",
			onDisk:    []string{"alpine", "alma", "rhel"},
			requested: []string{"alma", "rhel"},
			want:      []string{"alma", "rhel"},
		},
		{
			name:      "filter preserves on-disk order",
			onDisk:    []string{"alpine", "alma", "rhel"},
			requested: []string{"rhel", "alpine"},
			want:      []string{"alpine", "rhel"},
		},
		{
			name:      "missing provider returns error",
			onDisk:    []string{"alpine"},
			requested: []string{"alpine", "wolfi"},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateRequestedProviders(tt.onDisk, tt.requested)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
