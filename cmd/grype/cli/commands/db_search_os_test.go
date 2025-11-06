package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisplayDBOSTable(t *testing.T) {
	operatingSystems := []operatingSystem{
		{
			Name: "ubuntu",
			Versions: []osVersion{
				{Value: "20.04", Codename: "focal"},
				{Value: "20.10", Codename: "groovy"},
			},
			ReleaseID: "ubuntu",
			Channel:   "",
			Provider:  "ubuntu",
		},
		{
			Name: "debian",
			Versions: []osVersion{
				{Value: "10", Codename: "buster"},
				{Value: "11", Codename: "bullseye"},
			},
			ReleaseID: "debian",
			Channel:   "",
			Provider:  "debian",
		},
		{
			Name: "rhel",
			Versions: []osVersion{
				{Value: "8.1"},
				{Value: "8.2"},
			},
			ReleaseID: "rhel",
			Channel:   "eus",
			Provider:  "rhel",
		},
	}

	expectedOutput := `NAME    VERSIONS      CHANNEL  PROVIDER
ubuntu  20.04, 20.10  -        ubuntu
debian  10, 11        -        debian
rhel    8.1, 8.2      eus      rhel
`

	var output bytes.Buffer
	require.NoError(t, displayDBOSTable(operatingSystems, &output))

	// normalize whitespace for comparison
	normalize := func(s string) string {
		var normalized []string
		for _, line := range strings.Split(s, "\n") {
			normalized = append(normalized, strings.TrimRight(line, " \t"))
		}
		return strings.Join(normalized, "\n")
	}

	require.Equal(t, normalize(expectedOutput), normalize(output.String()))
}

func TestDisplayDBOSJSON(t *testing.T) {
	operatingSystems := []operatingSystem{
		{
			Name: "ubuntu",
			Versions: []osVersion{
				{Value: "20.04", Codename: "focal"},
				{Value: "20.10", Codename: "groovy"},
			},
			ReleaseID: "ubuntu",
			Channel:   "",
			Provider:  "ubuntu",
		},
		{
			Name: "debian",
			Versions: []osVersion{
				{Value: "10", Codename: "buster"},
				{Value: "11", Codename: "bullseye"},
			},
			ReleaseID: "debian",
			Channel:   "",
			Provider:  "debian",
		},
	}

	expectedJSON := `[
 {
  "name": "ubuntu",
  "versions": [
   {"value": "20.04", "codename": "focal"},
   {"value": "20.10", "codename": "groovy"}
  ],
  "releaseId": "ubuntu",
  "provider": "ubuntu"
 },
 {
  "name": "debian",
  "versions": [
   {"value": "10", "codename": "buster"},
   {"value": "11", "codename": "bullseye"}
  ],
  "releaseId": "debian",
  "provider": "debian"
 }
]
`

	var output bytes.Buffer
	err := displayDBOSJSON(operatingSystems, &output)
	require.NoError(t, err)

	require.JSONEq(t, expectedJSON, output.String())
}

func TestApplyArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expected    dbSearchOSOptions
		expectedErr string
	}{
		{
			name: "single name",
			args: []string{"ubuntu"},
			expected: dbSearchOSOptions{
				Name: "ubuntu",
			},
		},
		{
			name: "name@version",
			args: []string{"ubuntu@20.04"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "20.04",
			},
		},
		{
			name: "name@codename",
			args: []string{"ubuntu@focal"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "focal",
			},
		},
		{
			name: "name@version+channel",
			args: []string{"rhel@8.1+eus"},
			expected: dbSearchOSOptions{
				Name:    "rhel",
				Version: "8.1",
				Channel: "eus",
			},
		},
		{
			name: "version with dots",
			args: []string{"20.04"},
			expected: dbSearchOSOptions{
				Version: "20.04",
			},
		},
		{
			name: "version+channel",
			args: []string{"8.1+eus"},
			expected: dbSearchOSOptions{
				Version: "8.1",
				Channel: "eus",
			},
		},
		{
			name: "codename alone",
			args: []string{"focal"},
			expected: dbSearchOSOptions{
				Name: "focal", // ambiguous, treated as name first
			},
		},
		{
			name: "codename+channel",
			args: []string{"focal+eus"},
			expected: dbSearchOSOptions{
				Name:    "focal",
				Channel: "eus",
			},
		},
		{
			name: "multiple args - name and version",
			args: []string{"ubuntu", "20.04"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "20.04",
			},
		},
		{
			name: "multiple args - name and codename",
			args: []string{"ubuntu", "focal"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "focal",
			},
		},
		{
			name:        "multiple args - name, version, channel",
			args:        []string{"ubuntu", "20.04", "eus"},
			expectedErr: "ambiguous argument",
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: dbSearchOSOptions{},
		},
		{
			name:     "empty string ignored",
			args:     []string{""},
			expected: dbSearchOSOptions{},
		},
		{
			name: "ambiguous args - treated as name then version",
			args: []string{"ubuntu", "debian"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "debian", // second arg treated as version since name is taken
			},
		},
		{
			name:        "conflicting names in compound",
			args:        []string{"ubuntu@focal", "debian@buster"},
			expectedErr: "conflicting OS name",
		},
		{
			name:        "conflicting versions",
			args:        []string{"20.04", "22.04"},
			expectedErr: "conflicting version",
		},
		{
			name:        "conflicting versions and channels",
			args:        []string{"8.1+eus", "8.2+els"},
			expectedErr: "conflicting version", // version conflicts first
		},
		{
			name: "matching channels OK",
			args: []string{"8.1+eus", "focal+eus"},
			expected: dbSearchOSOptions{
				Version: "8.1",
				Name:    "focal",
				Channel: "eus",
			},
		},
		{
			name: "release ID",
			args: []string{"ol"},
			expected: dbSearchOSOptions{
				Name: "ol",
			},
		},
		{
			name: "release ID with version",
			args: []string{"ol@8.5"},
			expected: dbSearchOSOptions{
				Name:    "ol",
				Version: "8.5",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &dbSearchOSOptions{}
			err := opts.applyArgs(tt.args)

			if tt.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.Name, opts.Name, "name mismatch")
			require.Equal(t, tt.expected.Version, opts.Version, "version mismatch")
			require.Equal(t, tt.expected.Channel, opts.Channel, "channel mismatch")
		})
	}
}

func TestApplyArgsWithFlags(t *testing.T) {
	tests := []struct {
		name        string
		flags       dbSearchOSOptions
		args        []string
		expected    dbSearchOSOptions
		expectedErr string
	}{
		{
			name:  "args add to empty flags",
			flags: dbSearchOSOptions{},
			args:  []string{"ubuntu@20.04"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "20.04",
			},
		},
		{
			name: "args match existing flags",
			flags: dbSearchOSOptions{
				Name: "ubuntu",
			},
			args: []string{"ubuntu@20.04"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "20.04",
			},
		},
		{
			name: "ambiguous arg with existing name treated as version",
			flags: dbSearchOSOptions{
				Name: "ubuntu",
			},
			args: []string{"debian"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "debian", // ambiguous arg treated as version since name exists
			},
		},
		{
			name: "args conflict with flags - version",
			flags: dbSearchOSOptions{
				Version: "20.04",
			},
			args:        []string{"22.04"},
			expectedErr: "conflicting version",
		},
		{
			name: "args conflict with flags - channel",
			flags: dbSearchOSOptions{
				Channel: "eus",
			},
			args:        []string{"focal+els"},
			expectedErr: "conflicting channel",
		},
		{
			name: "args complement flags",
			flags: dbSearchOSOptions{
				Name: "ubuntu",
			},
			args: []string{"focal"},
			expected: dbSearchOSOptions{
				Name:    "ubuntu",
				Version: "focal",
			},
		},
		{
			name: "explicit name conflict with flags",
			flags: dbSearchOSOptions{
				Name: "ubuntu",
			},
			args:        []string{"debian@buster"},
			expectedErr: "conflicting OS name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.flags
			err := opts.applyArgs(tt.args)

			if tt.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.Name, opts.Name, "name mismatch")
			require.Equal(t, tt.expected.Version, opts.Version, "version mismatch")
			require.Equal(t, tt.expected.Channel, opts.Channel, "channel mismatch")
		})
	}
}

func TestParseSearchOptions(t *testing.T) {
	tests := []struct {
		name        string
		opts        dbSearchOSOptions
		expected    parsedSearchOptions
		expectedErr string
	}{
		{
			name: "simple name",
			opts: dbSearchOSOptions{Name: "ubuntu"},
			expected: parsedSearchOptions{
				name: "ubuntu",
			},
		},
		{
			name: "name@version syntax",
			opts: dbSearchOSOptions{Name: "ubuntu@20.04"},
			expected: parsedSearchOptions{
				name:    "ubuntu",
				version: "20.04",
			},
		},
		{
			name: "version with channel suffix",
			opts: dbSearchOSOptions{Version: "8.1+eus"},
			expected: parsedSearchOptions{
				version: "8.1",
				channel: "eus",
			},
		},
		{
			name: "explicit channel matches version channel",
			opts: dbSearchOSOptions{Version: "8.1+eus", Channel: "eus"},
			expected: parsedSearchOptions{
				version: "8.1",
				channel: "eus",
			},
		},
		{
			name:        "conflicting channels",
			opts:        dbSearchOSOptions{Version: "8.1+eus", Channel: "els"},
			expectedErr: "conflicting channel specified",
		},
		{
			name: "version as codename",
			opts: dbSearchOSOptions{Version: "focal"},
			expected: parsedSearchOptions{
				version: "focal",
			},
		},
		{
			name:        "conflicting name@version and --version",
			opts:        dbSearchOSOptions{Name: "ubuntu@20.04", Version: "22.04"},
			expectedErr: "conflicting version specified",
		},
		{
			name: "matching name@version and --version",
			opts: dbSearchOSOptions{Name: "ubuntu@20.04", Version: "20.04"},
			expected: parsedSearchOptions{
				name:    "ubuntu",
				version: "20.04",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSearchOptions(tt.opts)
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterOperatingSystems(t *testing.T) {
	allOS := []operatingSystem{
		{
			Name: "ubuntu",
			Versions: []osVersion{
				{Value: "20.04", Codename: "focal"},
				{Value: "20.10", Codename: "groovy"},
				{Value: "22.04", Codename: "jammy"},
			},
			Channel:  "",
			Provider: "ubuntu",
		},
		{
			Name: "debian",
			Versions: []osVersion{
				{Value: "10", Codename: "buster"},
				{Value: "11", Codename: "bullseye"},
			},
			Channel:  "",
			Provider: "debian",
		},
		{
			Name: "rhel",
			Versions: []osVersion{
				{Value: "8.1"},
				{Value: "8.2"},
			},
			Channel:  "eus",
			Provider: "rhel",
		},
	}

	tests := []struct {
		name     string
		opts     parsedSearchOptions
		expected []operatingSystem
	}{
		{
			name:     "no filters returns all",
			opts:     parsedSearchOptions{},
			expected: allOS,
		},
		{
			name: "filter by name",
			opts: parsedSearchOptions{name: "ubuntu"},
			expected: []operatingSystem{
				{
					Name: "ubuntu",
					Versions: []osVersion{
						{Value: "20.04", Codename: "focal"},
						{Value: "20.10", Codename: "groovy"},
						{Value: "22.04", Codename: "jammy"},
					},
					Channel:  "",
					Provider: "ubuntu",
				},
			},
		},
		{
			name: "filter by version number",
			opts: parsedSearchOptions{version: "20.04"},
			expected: []operatingSystem{
				{
					Name: "ubuntu",
					Versions: []osVersion{
						{Value: "20.04", Codename: "focal"},
					},
					Channel:  "",
					Provider: "ubuntu",
				},
			},
		},
		{
			name: "filter by codename",
			opts: parsedSearchOptions{version: "focal"},
			expected: []operatingSystem{
				{
					Name: "ubuntu",
					Versions: []osVersion{
						{Value: "20.04", Codename: "focal"},
					},
					Channel:  "",
					Provider: "ubuntu",
				},
			},
		},
		{
			name: "filter by channel",
			opts: parsedSearchOptions{channel: "eus"},
			expected: []operatingSystem{
				{
					Name: "rhel",
					Versions: []osVersion{
						{Value: "8.1"},
						{Value: "8.2"},
					},
					Channel:  "eus",
					Provider: "rhel",
				},
			},
		},
		{
			name: "filter by name and version",
			opts: parsedSearchOptions{name: "ubuntu", version: "jammy"},
			expected: []operatingSystem{
				{
					Name: "ubuntu",
					Versions: []osVersion{
						{Value: "22.04", Codename: "jammy"},
					},
					Channel:  "",
					Provider: "ubuntu",
				},
			},
		},
		{
			name: "case insensitive name filter",
			opts: parsedSearchOptions{name: "UBUNTU"},
			expected: []operatingSystem{
				{
					Name: "ubuntu",
					Versions: []osVersion{
						{Value: "20.04", Codename: "focal"},
						{Value: "20.10", Codename: "groovy"},
						{Value: "22.04", Codename: "jammy"},
					},
					Channel:  "",
					Provider: "ubuntu",
				},
			},
		},
		{
			name:     "no matches returns empty",
			opts:     parsedSearchOptions{name: "nonexistent"},
			expected: []operatingSystem{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterOperatingSystems(allOS, tt.opts)
			require.ElementsMatch(t, tt.expected, result)
		})
	}
}
