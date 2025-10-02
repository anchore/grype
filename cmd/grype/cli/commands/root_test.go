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
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	vexStatus "github.com/anchore/grype/grype/vex/status"
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
								Name:     "eus",
								IDs:      []string{"rhel"},
								Apply:    "auto",
								Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
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

func Test_getMatcherConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *options.Grype
		want matcher.Config
	}{
		{
			name: "default options",
			opts: options.DefaultGrype(clio.Identification{
				Name:    "test",
				Version: "1.0",
			}),
			want: matcher.Config{
				Java: java.MatcherConfig{
					ExternalSearchConfig: java.ExternalSearchConfig{
						SearchMavenUpstream: false,
						MavenBaseURL:        "https://search.maven.org/solrsearch/select",
						MavenRateLimit:      300000000, // 300ms in nanoseconds
					},
					UseCPEs: false,
				},
				Ruby:       ruby.MatcherConfig{},
				Python:     python.MatcherConfig{},
				Dotnet:     dotnet.MatcherConfig{},
				Javascript: javascript.MatcherConfig{},
				Golang: golang.MatcherConfig{
					UseCPEs:                                false,
					AlwaysUseCPEForStdlib:                  true,
					AllowMainModulePseudoVersionComparison: false,
				},
				Stock: stock.MatcherConfig{UseCPEs: true},
				Rpm: rpm.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              true,
				},
				Dpkg: dpkg.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              true,
				},
			},
		},
		{
			name: "rpm missing-epoch-strategy set to auto",
			opts: func() *options.Grype {
				opts := options.DefaultGrype(clio.Identification{Name: "test", Version: "1.0"})
				opts.Match.Rpm.MissingEpochStrategy = "auto"
				return opts
			}(),
			want: matcher.Config{
				Java: java.MatcherConfig{
					ExternalSearchConfig: java.ExternalSearchConfig{
						SearchMavenUpstream: false,
						MavenBaseURL:        "https://search.maven.org/solrsearch/select",
						MavenRateLimit:      300000000,
					},
					UseCPEs: false,
				},
				Ruby:       ruby.MatcherConfig{},
				Python:     python.MatcherConfig{},
				Dotnet:     dotnet.MatcherConfig{},
				Javascript: javascript.MatcherConfig{},
				Golang: golang.MatcherConfig{
					UseCPEs:                                false,
					AlwaysUseCPEForStdlib:                  true,
					AllowMainModulePseudoVersionComparison: false,
				},
				Stock: stock.MatcherConfig{UseCPEs: true},
				Rpm: rpm.MatcherConfig{
					MissingEpochStrategy: "auto",
					UseCPEs:              true,
				},
				Dpkg: dpkg.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              true,
				},
			},
		},
		{
			name: "dpkg missing-epoch-strategy set to auto",
			opts: func() *options.Grype {
				opts := options.DefaultGrype(clio.Identification{Name: "test", Version: "1.0"})
				opts.Match.Dpkg.MissingEpochStrategy = "auto"
				return opts
			}(),
			want: matcher.Config{
				Java: java.MatcherConfig{
					ExternalSearchConfig: java.ExternalSearchConfig{
						SearchMavenUpstream: false,
						MavenBaseURL:        "https://search.maven.org/solrsearch/select",
						MavenRateLimit:      300000000,
					},
					UseCPEs: false,
				},
				Ruby:       ruby.MatcherConfig{},
				Python:     python.MatcherConfig{},
				Dotnet:     dotnet.MatcherConfig{},
				Javascript: javascript.MatcherConfig{},
				Golang: golang.MatcherConfig{
					UseCPEs:                                false,
					AlwaysUseCPEForStdlib:                  true,
					AllowMainModulePseudoVersionComparison: false,
				},
				Stock: stock.MatcherConfig{UseCPEs: true},
				Rpm: rpm.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              true,
				},
				Dpkg: dpkg.MatcherConfig{
					MissingEpochStrategy: "auto",
					UseCPEs:              true,
				},
			},
		},
		{
			name: "rpm and dpkg with UseCPEs disabled",
			opts: func() *options.Grype {
				opts := options.DefaultGrype(clio.Identification{Name: "test", Version: "1.0"})
				opts.Match.Rpm.UseCPEs = false
				opts.Match.Dpkg.UseCPEs = false
				return opts
			}(),
			want: matcher.Config{
				Java: java.MatcherConfig{
					ExternalSearchConfig: java.ExternalSearchConfig{
						SearchMavenUpstream: false,
						MavenBaseURL:        "https://search.maven.org/solrsearch/select",
						MavenRateLimit:      300000000,
					},
					UseCPEs: false,
				},
				Ruby:       ruby.MatcherConfig{},
				Python:     python.MatcherConfig{},
				Dotnet:     dotnet.MatcherConfig{},
				Javascript: javascript.MatcherConfig{},
				Golang: golang.MatcherConfig{
					UseCPEs:                                false,
					AlwaysUseCPEForStdlib:                  true,
					AllowMainModulePseudoVersionComparison: false,
				},
				Stock: stock.MatcherConfig{UseCPEs: true},
				Rpm: rpm.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              false,
				},
				Dpkg: dpkg.MatcherConfig{
					MissingEpochStrategy: "zero",
					UseCPEs:              false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := cmp.Diff(tt.want, getMatcherConfig(tt.opts)); d != "" {
				t.Errorf("getMatcherConfig() mismatch (-want +got):\n%s", d)
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
				{VexStatus: string(vexStatus.NotAffected)},
				{VexStatus: string(vexStatus.Fixed)},
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
				{VexStatus: string(vexStatus.NotAffected)},
				{VexStatus: string(vexStatus.Fixed)},
			},
			expectError: false,
		},
		{
			name:               "vex-add with valid statuses",
			initialIgnoreRules: []match.IgnoreRule{},
			vexDocuments:       []string{"path/to/vex.json"},
			vexAdd:             []string{"affected", "under_investigation"},
			expectedIgnoreRules: []match.IgnoreRule{
				{VexStatus: string(vexStatus.NotAffected)},
				{VexStatus: string(vexStatus.Fixed)},
				{VexStatus: string(vexStatus.Affected)},
				{VexStatus: string(vexStatus.UnderInvestigation)},
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
				{VexStatus: string(vexStatus.NotAffected)},
				{VexStatus: string(vexStatus.Fixed)},
				{VexStatus: string(vexStatus.Affected)},
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
