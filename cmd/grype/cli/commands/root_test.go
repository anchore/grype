package commands

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

func Test_getProviderConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *options.Grype
		want pkg.ProviderConfig
	}{
		{
			name: "syft default api options are used",
			opts: options.DefaultGrype(clio.Identification{
				Name:    "test",
				Version: "1.0",
			}),
			want: pkg.ProviderConfig{
				SyftProviderConfig: pkg.SyftProviderConfig{
					SBOMOptions: func() *syft.CreateSBOMConfig {
						cfg := syft.DefaultCreateSBOMConfig()
						cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop
						return cfg
					}(),
					RegistryOptions: &image.RegistryOptions{
						Credentials: []image.RegistryCredentials{},
					},
				},
				SynthesisConfig: pkg.SynthesisConfig{
					GenerateMissingCPEs: false,
					Distro: pkg.DistroConfig{
						Override: nil,
						FixChannels: []distro.FixChannel{
							{
								Name:  "eus",
								IDs:   []string{"rhel"},
								Apply: "auto",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := cmp.Options{
				cmpopts.IgnoreFields(binary.Classifier{}, "EvidenceMatcher"),
				cmpopts.IgnoreUnexported(syft.CreateSBOMConfig{}),
			}
			if d := cmp.Diff(tt.want, getProviderConfig(tt.opts), opts...); d != "" {
				t.Errorf("getProviderConfig() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func Test_applyVexRules(t *testing.T) {
	tests := []struct {
		name                   string
		initialIgnoreRules     []match.IgnoreRule
		vexDocuments           []string
		vexAdd                 []string
		expectedIgnoreRules    []match.IgnoreRule
		expectError            bool
		expectedErrorSubstring string
	}{
		{
			name:                "no VEX documents provided - no rules added",
			initialIgnoreRules:  []match.IgnoreRule{},
			vexDocuments:        []string{},
			vexAdd:              []string{},
			expectedIgnoreRules: []match.IgnoreRule{},
			expectError:         false,
		},
		{
			name:               "VEX documents provided with empty ignore rules - automatic rules added",
			initialIgnoreRules: []match.IgnoreRule{},
			vexDocuments:       []string{"path/to/vex.json"},
			vexAdd:             []string{},
			expectedIgnoreRules: []match.IgnoreRule{
				{VexStatus: string(vex.StatusNotAffected)},
				{VexStatus: string(vex.StatusFixed)},
			},
			expectError: false,
		},
		{
			name: "VEX documents provided with existing ignore rules - automatic rules still added",
			initialIgnoreRules: []match.IgnoreRule{
				{Vulnerability: "CVE-2023-1234"},
			},
			vexDocuments: []string{"path/to/vex.json"},
			vexAdd:       []string{},
			expectedIgnoreRules: []match.IgnoreRule{
				{Vulnerability: "CVE-2023-1234"},
				{VexStatus: string(vex.StatusNotAffected)},
				{VexStatus: string(vex.StatusFixed)},
			},
			expectError: false,
		},
		{
			name:               "vex-add with valid statuses",
			initialIgnoreRules: []match.IgnoreRule{},
			vexDocuments:       []string{"path/to/vex.json"},
			vexAdd:             []string{"affected", "under_investigation"},
			expectedIgnoreRules: []match.IgnoreRule{
				{VexStatus: string(vex.StatusNotAffected)},
				{VexStatus: string(vex.StatusFixed)},
				{VexStatus: string(vex.StatusAffected)},
				{VexStatus: string(vex.StatusUnderInvestigation)},
			},
			expectError: false,
		},
		{
			name:                   "vex-add with invalid status",
			initialIgnoreRules:     []match.IgnoreRule{},
			vexDocuments:           []string{"path/to/vex.json"},
			vexAdd:                 []string{"invalid_status"},
			expectedIgnoreRules:    nil,
			expectError:            true,
			expectedErrorSubstring: "invalid VEX status in vex-add setting: invalid_status",
		},
		{
			name:                   "vex-add attempting to use fixed status",
			initialIgnoreRules:     []match.IgnoreRule{},
			vexDocuments:           []string{"path/to/vex.json"},
			vexAdd:                 []string{"fixed"},
			expectedIgnoreRules:    nil,
			expectError:            true,
			expectedErrorSubstring: "invalid VEX status in vex-add setting: fixed",
		},
		{
			name: "multiple VEX documents with existing rules",
			initialIgnoreRules: []match.IgnoreRule{
				{Vulnerability: "CVE-2023-1234"},
				{FixState: "unknown"},
			},
			vexDocuments: []string{"vex1.json", "vex2.json"},
			vexAdd:       []string{"affected"},
			expectedIgnoreRules: []match.IgnoreRule{
				{Vulnerability: "CVE-2023-1234"},
				{FixState: "unknown"},
				{VexStatus: string(vex.StatusNotAffected)},
				{VexStatus: string(vex.StatusFixed)},
				{VexStatus: string(vex.StatusAffected)},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &options.Grype{
				Ignore:       append([]match.IgnoreRule{}, tt.initialIgnoreRules...),
				VexDocuments: tt.vexDocuments,
				VexAdd:       tt.vexAdd,
			}

			err := applyVexRules(opts)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrorSubstring)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedIgnoreRules, opts.Ignore)
		})
	}
}
