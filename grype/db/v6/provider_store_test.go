package v6

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderStore(t *testing.T) {
	now := time.Date(2021, 1, 1, 2, 3, 4, 5, time.UTC)
	other := time.Date(2022, 2, 3, 4, 5, 6, 7, time.UTC)
	tests := []struct {
		name      string
		providers []Provider
		wantErr   require.ErrorAssertionFunc
	}{
		{
			name: "add new provider",
			providers: []Provider{
				{
					ID:           "ubuntu",
					Version:      "1.0",
					Processor:    "vunnel",
					DateCaptured: &now,
					InputDigest:  "sha256:abcd1234",
				},
			},
		},
		{
			name: "add existing provider",
			providers: []Provider{
				{ // original
					ID:           "ubuntu",
					Version:      "1.0",
					Processor:    "vunnel",
					DateCaptured: &now,
					InputDigest:  "sha256:abcd1234",
				},
				{ //  overwrite...
					ID:           "ubuntu",
					Version:      "2.0",
					Processor:    "something-else",
					DateCaptured: &other,
					InputDigest:  "sha256:cdef5678",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newProviderStore(setupTestStore(t).db)
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			for i, p := range tt.providers {
				isLast := i == len(tt.providers)-1
				err := s.AddProvider(&p)
				if !isLast {
					require.NoError(t, err)
					continue
				}

				tt.wantErr(t, err)
				if err != nil {
					continue
				}

				provider, err := s.GetProvider(p.ID)
				tt.wantErr(t, err)
				if err != nil {
					assert.Nil(t, provider)
					return
				}

				require.NoError(t, err)
				require.NotNil(t, provider)
				if d := cmp.Diff(p, *provider); d != "" {
					t.Errorf("unexpected provider (-want +got): %s", d)
				}
			}
		})
	}
}

func TestProviderStore_GetProvider(t *testing.T) {
	s := newProviderStore(setupTestStore(t).db)
	p, err := s.GetProvider("fake")
	require.Error(t, err)
	assert.Nil(t, p)
}
