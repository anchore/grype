package dbtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		pattern    string
		want       bool
	}{
		// CVE ID only (suffix match)
		{
			name:       "CVE ID matches any namespace",
			identifier: "debian:10/CVE-2024-1234",
			pattern:    "CVE-2024-1234",
			want:       true,
		},
		{
			name:       "CVE ID matches different namespace",
			identifier: "ubuntu:20.04/CVE-2024-1234",
			pattern:    "CVE-2024-1234",
			want:       true,
		},
		{
			name:       "CVE ID does not match different CVE",
			identifier: "debian:10/CVE-2024-5678",
			pattern:    "CVE-2024-1234",
			want:       false,
		},

		// namespace only (prefix match)
		{
			name:       "namespace matches all CVEs",
			identifier: "debian:10/CVE-2024-1234",
			pattern:    "debian:10",
			want:       true,
		},
		{
			name:       "namespace does not match different namespace",
			identifier: "debian:11/CVE-2024-1234",
			pattern:    "debian:10",
			want:       false,
		},
		{
			name:       "namespace partial match should not work",
			identifier: "debian:10-backports/CVE-2024-1234",
			pattern:    "debian:10",
			want:       false, // must be exact namespace match before /
		},

		// full identifier (exact match)
		{
			name:       "full identifier exact match",
			identifier: "debian:10/CVE-2024-1234",
			pattern:    "debian:10/CVE-2024-1234",
			want:       true,
		},
		{
			name:       "full identifier different namespace",
			identifier: "debian:11/CVE-2024-1234",
			pattern:    "debian:10/CVE-2024-1234",
			want:       false,
		},
		{
			name:       "full identifier different CVE",
			identifier: "debian:10/CVE-2024-5678",
			pattern:    "debian:10/CVE-2024-1234",
			want:       false,
		},

		// case insensitivity
		{
			name:       "CVE ID case insensitive - lowercase pattern",
			identifier: "debian:10/CVE-2024-1234",
			pattern:    "cve-2024-1234",
			want:       true,
		},
		{
			name:       "CVE ID case insensitive - uppercase identifier",
			identifier: "DEBIAN:10/CVE-2024-1234",
			pattern:    "cve-2024-1234",
			want:       true,
		},
		{
			name:       "namespace case insensitive",
			identifier: "DEBIAN:10/CVE-2024-1234",
			pattern:    "debian:10",
			want:       true,
		},
		{
			name:       "full identifier case insensitive",
			identifier: "DEBIAN:10/CVE-2024-1234",
			pattern:    "debian:10/cve-2024-1234",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPattern(tt.identifier, tt.pattern)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesSelection(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		patterns   []string
		want       bool
	}{
		{
			name:       "empty patterns matches all",
			identifier: "debian:10/CVE-2024-1234",
			patterns:   nil,
			want:       true,
		},
		{
			name:       "single CVE pattern match",
			identifier: "debian:10/CVE-2024-1234",
			patterns:   []string{"CVE-2024-1234"},
			want:       true,
		},
		{
			name:       "multiple patterns - first matches",
			identifier: "debian:10/CVE-2024-1234",
			patterns:   []string{"CVE-2024-1234", "debian:11"},
			want:       true,
		},
		{
			name:       "multiple patterns - second matches",
			identifier: "debian:11/CVE-2024-5678",
			patterns:   []string{"CVE-2024-1234", "debian:11"},
			want:       true,
		},
		{
			name:       "multiple patterns - none match",
			identifier: "ubuntu:20.04/CVE-2024-9999",
			patterns:   []string{"CVE-2024-1234", "debian:11"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesSelection(tt.identifier, tt.patterns)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResultIdentifier(t *testing.T) {
	// create a temp file with valid JSON
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid.json")
	err := os.WriteFile(validFile, []byte(`{"identifier": "debian:10/CVE-2024-1234", "schema": "test"}`), 0644)
	require.NoError(t, err)

	// test reading identifier
	id, err := resultIdentifier(validFile)
	require.NoError(t, err)
	assert.Equal(t, "debian:10/CVE-2024-1234", id)

	// test file without identifier
	noIdFile := filepath.Join(tmpDir, "no-id.json")
	err = os.WriteFile(noIdFile, []byte(`{"schema": "test"}`), 0644)
	require.NoError(t, err)

	id, err = resultIdentifier(noIdFile)
	require.NoError(t, err)
	assert.Empty(t, id)

	// test non-existent file
	_, err = resultIdentifier(filepath.Join(tmpDir, "nonexistent.json"))
	assert.Error(t, err)
}

func TestFilterResultFiles(t *testing.T) {
	// create temp directory with test files
	tmpDir := t.TempDir()

	files := map[string]string{
		"cve1.json": `{"identifier": "debian:10/CVE-2024-0001"}`,
		"cve2.json": `{"identifier": "debian:10/CVE-2024-0002"}`,
		"cve3.json": `{"identifier": "debian:11/CVE-2024-0001"}`,
		"cve4.json": `{"identifier": "debian:11/CVE-2024-0003"}`,
	}

	var paths []string
	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(content), 0644)
		require.NoError(t, err)
		paths = append(paths, path)
	}

	tests := []struct {
		name      string
		patterns  []string
		wantCount int
	}{
		{
			name:      "no patterns returns all",
			patterns:  nil,
			wantCount: 4,
		},
		{
			name:      "select by CVE across namespaces",
			patterns:  []string{"CVE-2024-0001"},
			wantCount: 2, // debian:10 and debian:11 versions
		},
		{
			name:      "select by namespace",
			patterns:  []string{"debian:10"},
			wantCount: 2, // all debian:10 CVEs
		},
		{
			name:      "select by exact identifier",
			patterns:  []string{"debian:11/CVE-2024-0003"},
			wantCount: 1,
		},
		{
			name:      "multiple patterns union",
			patterns:  []string{"CVE-2024-0002", "debian:11"},
			wantCount: 3, // CVE-2024-0002 + both debian:11 CVEs
		},
		{
			name:      "no matches",
			patterns:  []string{"CVE-9999-9999"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := filterResultFiles(paths, tt.patterns)
			assert.Len(t, matched, tt.wantCount)
		})
	}
}
