package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/tests"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
)

func mockGithubProcessorTransform(vulnerability unmarshal.GitHubAdvisory) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestGitHubProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/github.json")
	require.NoError(t, err)
	defer tests.CloseFile(f)

	processor := NewGitHubProcessor(mockGithubProcessorTransform)
	entries, err := processor.Process(f, provider.State{
		Provider: "github",
	})

	assert.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestGithubProcessor_IsSupported(t *testing.T) {
	tc := []struct {
		name      string
		schemaURL string
		expected  bool
	}{
		{
			name:      "valid schema URL with version 1.0.0",
			schemaURL: "https://example.com/vunnel/path/vulnerability/github-security-advisory/schema-1.0.0.json",
			expected:  true,
		},
		{
			name:      "valid schema URL with version 1.2.3",
			schemaURL: "https://example.com/vunnel/path/vulnerability/github-security-advisory/schema-1.2.3.json",
			expected:  true,
		},
		{
			name:      "invalid schema URL with unsupported version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/github-security-advisory/schema-2.0.0.json",
			expected:  false,
		},
		{
			name:      "invalid schema URL with missing version",
			schemaURL: "https://example.com/vunnel/path/vulnerability/github-security-advisory/schema.json",
			expected:  false,
		},
		{
			name:      "completely invalid URL",
			schemaURL: "https://example.com/invalid/schema/url",
			expected:  false,
		},
	}

	p := githubProcessor{}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.IsSupported(tt.schemaURL))
		})
	}
}
