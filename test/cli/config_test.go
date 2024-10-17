package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_configLoading(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer func() { require.NoError(t, os.Chdir(cwd)) }()

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
			require.NoError(t, os.Chdir(test.cwd))
			defer func() { require.NoError(t, os.Chdir(cwd)) }()
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
