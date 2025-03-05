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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestStore(t).db
			s := newProviderStore(db)
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			for i := range tt.providers {
				p := tt.providers[i]
				// note: we always write providers via the vulnerability handle (there is no store adder)
				vuln := VulnerabilityHandle{
					Name:     "CVE-1234-5678",
					Provider: &p,
				}
				isLast := i == len(tt.providers)-1
				err := db.Create(&vuln).Error
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
