package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_configLoading(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	configsDir := filepath.Join(cwd, "test-fixtures", "configs")
	path := func(path string) string {
		return filepath.Join(configsDir, filepath.Join(strings.Split(path, "/")...))
	}

	type ignore struct {
		Vuln string `yaml:"vulnerability"`
	}

	type config struct {
		Ignores []ignore `yaml:"ignore"`
	}

	tests := []struct {
		name     string
		home     string
		cwd      string
		args     []string
		expected []ignore
		err      string
	}{
		{
			name: "single explicit config",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.grype.yaml"),
			},
			expected: []ignore{
				{
					Vuln: "dir1-vuln1",
				},
				{
					Vuln: "dir1-vuln2",
				},
			},
		},
		{
			name: "multiple explicit config",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.grype.yaml"),
				"-c",
				path("dir2/.grype.yaml"),
			},
			expected: []ignore{
				{
					Vuln: "dir1-vuln1",
				},
				{
					Vuln: "dir1-vuln2",
				},
				{
					Vuln: "dir2-vuln1",
				},
				{
					Vuln: "dir2-vuln2",
				},
			},
		},
		{
			name: "empty profile override",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.grype.yaml"),
				"-c",
				path("dir2/.grype.yaml"),
				"--profile",
				"no-ignore",
			},
			expected: []ignore{},
		},
		{
			name: "no profiles defined",
			home: configsDir,
			cwd:  configsDir,
			args: []string{
				"-c",
				path("dir3/.grype.yaml"),
				"--profile",
				"invalid",
			},
			err: "not found in any configuration files",
		},
		{
			name: "invalid profile name",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.grype.yaml"),
				"-c",
				path("dir2/.grype.yaml"),
				"--profile",
				"alt",
			},
			err: "profile not found",
		},
		{
			name: "explicit with profile override",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.grype.yaml"),
				"-c",
				path("dir2/.grype.yaml"),
				"--profile",
				"alt-ignore",
			},
			expected: []ignore{
				{
					Vuln: "dir1-alt-vuln1", // dir1 is still first
				},
				{
					Vuln: "dir1-alt-vuln2", // dir1 is still first
				},
				{
					Vuln: "dir2-alt-vuln1",
				},
				{
					Vuln: "dir2-alt-vuln2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Chdir(test.cwd)
			env := map[string]string{
				"HOME":            test.home,
				"XDG_CONFIG_HOME": test.home,
			}
			_, stdout, stderr := runGrype(t, env, append([]string{"config", "--load"}, test.args...)...)
			if test.err != "" {
				require.Contains(t, stderr, test.err)
				return
			} else {
				require.Empty(t, stderr)
			}
			got := config{}
			err = yaml.NewDecoder(strings.NewReader(stdout)).Decode(&got)
			require.NoError(t, err)
			require.Equal(t, test.expected, got.Ignores)
		})
	}
}

func Test_dpkgUseCPEsForEOLEnvVar(t *testing.T) {
	// Test that GRYPE_MATCH_DPKG_USE_CPES_FOR_EOL env var is properly wired up
	type matchConfig struct {
		Dpkg struct {
			UseCPEsForEOL bool `yaml:"use-cpes-for-eol"`
		} `yaml:"dpkg"`
	}
	type testConfig struct {
		Match matchConfig `yaml:"match"`
	}

	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{
			name:     "env var true enables CPE matching for EOL",
			envValue: "true",
			expected: true,
		},
		{
			name:     "env var false disables CPE matching for EOL",
			envValue: "false",
			expected: false,
		},
		{
			name:     "default is false",
			envValue: "",
			expected: false,
		},
	}

	// Create a minimal config file for testing
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".grype.yaml")
	err := os.WriteFile(cfgPath, []byte("check-for-app-update: false\n"), 0644)
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := map[string]string{
				"HOME":            tmpDir,
				"XDG_CONFIG_HOME": tmpDir,
			}
			if test.envValue != "" {
				env["GRYPE_MATCH_DPKG_USE_CPES_FOR_EOL"] = test.envValue
			}

			_, stdout, stderr := runGrype(t, env, "-c", cfgPath, "config", "--load")
			require.Empty(t, stderr)

			got := testConfig{}
			err := yaml.NewDecoder(strings.NewReader(stdout)).Decode(&got)
			require.NoError(t, err)
			assert.Equal(t, test.expected, got.Match.Dpkg.UseCPEsForEOL,
				"expected match.dpkg.use-cpes-for-eol to be %v", test.expected)
		})
	}
}
