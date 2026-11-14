package commands

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemePrefixCompletions(t *testing.T) {
	tests := []struct {
		name       string
		toComplete string
		want       []string
	}{
		{
			name:       "empty input returns all documented scheme prefixes",
			toComplete: "",
			want:       targetSchemePrefixes,
		},
		{
			name:       "single letter narrows to matching prefixes",
			toComplete: "o",
			want:       []string{"oci-archive:", "oci-dir:"},
		},
		{
			name:       "partial scheme returns just the matches",
			toComplete: "oci-",
			want:       []string{"oci-archive:", "oci-dir:"},
		},
		{
			name:       "exact partial returns the single match",
			toComplete: "sbom",
			want:       []string{"sbom:"},
		},
		{
			name:       "unrelated input returns no scheme matches",
			toComplete: "xyz",
			want:       []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := schemePrefixCompletions(tt.toComplete)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTargetSchemePrefixesCoverage(t *testing.T) {
	// every scheme documented in the root command long-help text should be in the completion list,
	// otherwise users typing one of those prefixes won't see it offered
	expected := []string{
		"docker:",
		"podman:",
		"docker-archive:",
		"oci-archive:",
		"oci-dir:",
		"singularity:",
		"registry:",
		"dir:",
		"file:",
		"sbom:",
		"purl:",
		"cpes:",
	}
	for _, p := range expected {
		assert.Containsf(t, targetSchemePrefixes, p, "scheme %q should be offered as a completion", p)
	}
	for _, p := range targetSchemePrefixes {
		assert.Truef(t, strings.HasSuffix(p, ":"), "scheme prefix %q must end in ':' so users can keep typing", p)
	}
}

func TestHasImageScheme(t *testing.T) {
	tests := []struct {
		input      string
		wantScheme string
		wantOK     bool
	}{
		{"docker:alpine", "docker:", true},
		{"docker:", "docker:", true},
		{"podman:fedora:39", "podman:", true},
		{"registry:gcr.io/foo", "", false},
		{"dir:/tmp", "", false},
		{"alpine:3.18", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			scheme, ok := hasImageScheme(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantScheme, scheme)
		})
	}
}

func TestHasAnyTargetScheme(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"docker:alpine", true},
		{"dir:/tmp/proj", true},
		{"sbom:./sbom.json", true},
		{"registry:gcr.io/foo", true},
		{"oci-archive:/tmp/img.tar", true},
		{"alpine:3.18", false},
		{"./local/path", false},
		{"", false},
		{"unknown-scheme:foo", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, hasAnyTargetScheme(tt.input))
		})
	}
}

func TestDockerImageValidArgsFunction_OffersSchemesOnEmptyInput(t *testing.T) {
	// when the user has typed nothing, the function should return every documented scheme prefix.
	// We don't care whether a docker daemon is reachable in CI; we only assert the scheme prefixes
	// are present in the suggestions. The directive should request NoSpace so that "dir:" can be
	// followed by a path without the shell adding a separator.
	cmd := &cobra.Command{Use: "grype"}
	got, directive := dockerImageValidArgsFunction(cmd, nil, "")
	for _, p := range targetSchemePrefixes {
		assert.Containsf(t, got, p, "expected scheme prefix %q in completions", p)
	}
	assert.NotZero(t, directive&cobra.ShellCompDirectiveNoSpace, "expected NoSpace directive bit so user can keep typing after the colon")
}

func TestDockerImageValidArgsFunction_FileSchemeFallsThroughToShell(t *testing.T) {
	// when a non-image scheme is in play, defer to the shell for path completion. We should return
	// no suggestions and the Default directive so the shell offers filename completion.
	cmd := &cobra.Command{Use: "grype"}
	got, directive := dockerImageValidArgsFunction(cmd, nil, "dir:/tmp/")
	assert.Empty(t, got)
	assert.Equal(t, cobra.ShellCompDirectiveDefault, directive)
}

func TestDockerImageValidArgsFunction_PartialSchemeNarrows(t *testing.T) {
	// when the user has typed a partial scheme that doesn't fully match any prefix, only matching
	// prefixes should be offered.
	cmd := &cobra.Command{Use: "grype"}
	got, _ := dockerImageValidArgsFunction(cmd, nil, "oci-")
	require.NotEmpty(t, got)
	assert.Contains(t, got, "oci-archive:")
	assert.Contains(t, got, "oci-dir:")
	for _, c := range got {
		// since we matched on "oci-", non-matching schemes should not be returned (docker-image
		// fallback is also limited by the same prefix on the daemon side, so we don't expect
		// arbitrary images either)
		assert.Truef(t, strings.HasPrefix(c, "oci-"), "completion %q should start with the partial 'oci-' the user typed", c)
	}
}
