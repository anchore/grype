package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRpmConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     rpmConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid zero strategy",
			cfg:     rpmConfig{MissingEpochStrategy: "zero"},
			wantErr: false,
		},
		{
			name:    "valid auto strategy",
			cfg:     rpmConfig{MissingEpochStrategy: "auto"},
			wantErr: false,
		},
		{
			name:    "invalid strategy",
			cfg:     rpmConfig{MissingEpochStrategy: "garbage"},
			wantErr: true,
			errMsg:  `invalid rpm.missing-epoch-strategy: "garbage" (allowable: zero, auto)`,
		},
		{
			name:    "empty strategy fails validation",
			cfg:     rpmConfig{MissingEpochStrategy: ""},
			wantErr: true,
			errMsg:  `invalid rpm.missing-epoch-strategy: "" (allowable: zero, auto)`,
		},
		{
			name:    "case sensitive - Zero is invalid",
			cfg:     rpmConfig{MissingEpochStrategy: "Zero"},
			wantErr: true,
		},
		{
			name:    "case sensitive - AUTO is invalid",
			cfg:     rpmConfig{MissingEpochStrategy: "AUTO"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.PostLoad()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDpkgConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     dpkgConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid zero strategy",
			cfg:     dpkgConfig{MissingEpochStrategy: "zero"},
			wantErr: false,
		},
		{
			name:    "valid auto strategy",
			cfg:     dpkgConfig{MissingEpochStrategy: "auto"},
			wantErr: false,
		},
		{
			name:    "invalid strategy",
			cfg:     dpkgConfig{MissingEpochStrategy: "invalid"},
			wantErr: true,
			errMsg:  `invalid dpkg.missing-epoch-strategy: "invalid" (allowable: zero, auto)`,
		},
		{
			name:    "empty strategy fails validation",
			cfg:     dpkgConfig{MissingEpochStrategy: ""},
			wantErr: true,
			errMsg:  `invalid dpkg.missing-epoch-strategy: "" (allowable: zero, auto)`,
		},
		{
			name:    "whitespace strategy is invalid",
			cfg:     dpkgConfig{MissingEpochStrategy: "  zero  "},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.PostLoad()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMatchConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     matchConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rpm and dpkg configs",
			cfg: matchConfig{
				Rpm:  rpmConfig{MissingEpochStrategy: "zero"},
				Dpkg: dpkgConfig{MissingEpochStrategy: "auto"},
			},
			wantErr: false,
		},
		{
			name: "invalid rpm config",
			cfg: matchConfig{
				Rpm:  rpmConfig{MissingEpochStrategy: "bad"},
				Dpkg: dpkgConfig{MissingEpochStrategy: "zero"},
			},
			wantErr: true,
			errMsg:  "rpm.missing-epoch-strategy",
		},
		{
			name: "invalid dpkg config",
			cfg: matchConfig{
				Rpm:  rpmConfig{MissingEpochStrategy: "zero"},
				Dpkg: dpkgConfig{MissingEpochStrategy: "bad"},
			},
			wantErr: true,
			errMsg:  "dpkg.missing-epoch-strategy",
		},
		{
			name: "both invalid",
			cfg: matchConfig{
				Rpm:  rpmConfig{MissingEpochStrategy: "bad"},
				Dpkg: dpkgConfig{MissingEpochStrategy: "bad"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.PostLoad()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultRpmConfig(t *testing.T) {
	cfg := defaultRpmConfig()
	assert.Equal(t, "zero", cfg.MissingEpochStrategy, "default should be zero for backward compatibility")
	assert.True(t, cfg.UseCPEs, "rpm matcher should use CPEs by default")

	// Ensure default is valid
	err := cfg.PostLoad()
	require.NoError(t, err, "default config should be valid")
}

func TestDefaultDpkgConfig(t *testing.T) {
	cfg := defaultDpkgConfig()
	assert.Equal(t, "zero", cfg.MissingEpochStrategy, "default should be zero for backward compatibility")
	assert.True(t, cfg.UseCPEs, "dpkg matcher should use CPEs by default")

	// Ensure default is valid
	err := cfg.PostLoad()
	require.NoError(t, err, "default config should be valid")
}

func TestDefaultMatchConfig(t *testing.T) {
	cfg := defaultMatchConfig()

	// Verify RPM defaults
	assert.Equal(t, "zero", cfg.Rpm.MissingEpochStrategy)
	assert.True(t, cfg.Rpm.UseCPEs)

	// Verify dpkg defaults
	assert.Equal(t, "zero", cfg.Dpkg.MissingEpochStrategy)
	assert.True(t, cfg.Dpkg.UseCPEs)

	// Ensure the entire default config is valid
	err := cfg.PostLoad()
	require.NoError(t, err, "default match config should be valid")
}
