package version

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_cleanPlatformMakesEqualVersions(t *testing.T) {
	tests := []struct {
		input   string
		trimmed string
		want    *gemVersion
	}{
		{input: "1.13.1", trimmed: "1.13.1"},
		{input: "1.13.1-arm-linux", trimmed: "1.13.1"},
		{input: "1.13.1-armv6-linux", trimmed: "1.13.1"},
		{input: "1.13.1-armv7-linux", trimmed: "1.13.1"},
		{input: "1.13.1-java", trimmed: "1.13.1"},
		{input: "1.13.1-dalvik", trimmed: "1.13.1"},
		{input: "1.13.1-mswin32", trimmed: "1.13.1"},
		{input: "1.13.1-x64-mswin64", trimmed: "1.13.1"},
		{input: "1.13.1-sparc-unix", trimmed: "1.13.1"},
		{input: "1.13.1-powerpc-darwin", trimmed: "1.13.1"},
		{input: "1.13.1-x86-linux", trimmed: "1.13.1"},
		{input: "1.13.1-x86_64-linux", trimmed: "1.13.1"},
		{input: "1.13.1-x86-freebsd", trimmed: "1.13.1"},
		{input: "1.13.1-x86-mswin32-80", trimmed: "1.13.1"},
		{input: "1.13.1-universal-darwin-8", trimmed: "1.13.1"},
		// ruby versions get the canonical segment "pre" if there are any segments that are all
		// alphabetic characters.
		{input: "1.13.1-beta-universal-darwin-8", trimmed: "1.13.1.pre.beta"},
		{input: "1.13.1-alpha-1-meta-arm-linux", trimmed: "1.13.1-alpha-1-meta"},
		{input: "1.13.1-alpha-1-build.12-arm-linux", trimmed: "1.13.1-alpha-1-build.12"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			original, err := NewVersion(tt.input, GemFormat)
			require.NoError(t, err)
			trimmed, err := NewVersion(tt.trimmed, GemFormat)
			require.NoError(t, err)
			comp, err := original.Compare(trimmed)
			require.NoError(t, err)
			assert.Equal(t, 0, comp)
			comp, err = trimmed.Compare(original)
			require.NoError(t, err)
			assert.Equal(t, 0, comp)
		})
	}
}

func TestNewRubyVersion_ValidInputs(t *testing.T) {
	tests := []struct {
		input              string
		expectedOriginal   string // What v.original should be
		expectedSegments   []any  // What v.segments should be (after .pre. processing)
		expectedPrerelease bool
	}{
		{"1.0", "1.0", []any{1, 0}, false},
		{"1.0 ", "1.0 ", []any{1, 0}, false}, // original preserves space
		{" 1.0 ", " 1.0 ", []any{1, 0}, false},
		{"1.2.3", "1.2.3", []any{1, 2, 3}, false},
		{"1.2.3.a", "1.2.3.a", []any{1, 2, 3, "a"}, true},
		{"1.2.3-b4", "1.2.3-b4", []any{1, 2, 3, "pre", "b", 4}, true},
		{"1", "1", []any{1}, false},
		{"0", "0", []any{0}, false},
		{"", "", []any{0}, false},     // Empty string becomes "0" effectively, original is ""
		{"  ", "  ", []any{0}, false}, // Whitespace string becomes "0" effectively
		{"1.0-alpha", "1.0-alpha", []any{1, 0, "pre", "alpha"}, true},
		{"1-1", "1-1", []any{1, "pre", 1}, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Input_%s", tt.input), func(t *testing.T) {
			v, err := newGemVersion(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedOriginal, v.original, "Original string mismatch")
			assert.Equal(t, tt.expectedSegments, v.segments, "Initial segments mismatch")
			assert.Equal(t, tt.expectedPrerelease, v.isPrerelease, "Prerelease flag mismatch")
		})
	}
}

func TestNewRubyVersion_InvalidInputs(t *testing.T) {
	invalidVersions := []struct {
		name           string
		input          string
		errorSubstring string
	}{
		{"newline", "1.0\n2.0", "malformed version number string"},
		{"double_dot", "1..2", "malformed version number string"},
		{"space_separated", "1.2 3.4", "malformed version number string"},
		{"trailing_dot_long", "1.2.", "leading/trailing dot"},
		{"leading_dot_long", ".1.2", "leading/trailing dot"},
		{"just_dot", ".", "no valid segments"},
		{"double_hyphen", "--", "malformed version number string"},
		{"hyphen_dot", "1.-2", "malformed version number string"},
		{"dot_hyphen", "1.-pre", "malformed version number string"},
		{"underscore", "1_2", "malformed version number string"},
		{"empty_segments", "...", "malformed version number string"},
		{"invalid_segment_char", "1.2.a@b", "malformed version number string"},
	}

	for _, tt := range invalidVersions {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newGemVersion(tt.input)
			require.Error(t, err)
			if tt.errorSubstring != "" {
				assert.Contains(t, err.Error(), tt.errorSubstring, "Error message mismatch for input: %s", tt.input)
			}
		})
	}
}

func TestRubyVersion_Compare(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int // expected result of v1.Compare(v2)
	}{
		// Basic comparisons (from Ruby's test_spaceship)
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.a", 1},
		{"1.8.2", "0.0.0", 1},
		{"1.8.2", "1.8.2.a", 1},
		{"1.8.2.b", "1.8.2.a", 1},
		{"1.8.2.a", "1.8.2", -1},
		{"1.8.2.a10", "1.8.2.a9", 1},
		{"", "0", 0}, // "" is treated as "0"

		// Canonicalization leading to equality
		{"0.beta.1", "0.0.beta.1", 0},  // Ruby: 0.beta.1 <=> 0.0.beta.1 is 0. Canonical for both is ["beta", -1]
		{"0.0.beta", "0.0.beta.1", -1}, // Ruby: 0.0.beta <=> 0.0.beta.1 is -1. Canonical ["beta"] vs ["beta", -1]

		// String segments comparison
		{"5.a", "5.0.0.rc2", -1}, // "a" < "rc"
		{"5.x", "5.0.0.rc2", 1},  // "x" > "rc"

		// Direct string comparison from Ruby test
		{"1.9.3", "1.9.3", 0},
		{"1.9.3", "1.9.2.99", 1},
		{"1.9.3", "1.9.3.1", -1},

		// Additional common cases
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1", "1.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},

		// Prerelease vs Prerelease (length diff)
		{"1.0.alpha.1", "1.0.alpha", 1},
		{"1.0.alpha", "1.0.alpha.1", -1},

		// Hyphen handling (SemVer-like via .pre.)
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1}, // beta < rc
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-1", "1", -1}, // 1.0.0.pre.1 vs 1
		{"1-1", "1", -1},     // 1.pre.1 vs 1

		// From Ruby's test_semver (some overlap, ensure coverage)
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-beta.2", -1}, // alpha < beta
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, // 2 < 11
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},   // beta < rc
		{"1.0.0-rc1", "1.0.0", -1},            // 1.0.0.pre.rc.1 < 1.0.0 (release)
		{"1.0.0-1", "1", -1},                  // 1.0.0.pre.1 < 1 (release)

		// Edge cases with canonicalization
		{"1.0", "1", 0},
		{"1.0.0", "1", 0},
		{"1.a", "1.0.0.a", 0}, // Canonical [1,"a"] for both
		{"1.a.0", "1.a", 0},   // Canonical [1,"a"] for both
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tt.v1, tt.v2), func(t *testing.T) {
			ver1, err := NewVersion(tt.v1, GemFormat)
			require.NoError(t, err)
			ver2, err := NewVersion(tt.v2, GemFormat)
			require.NoError(t, err)

			// Test v1 vs v2
			got1, err1 := ver1.Compare(ver2)
			require.NoError(t, err1, "v1.Compare(v2) failed for %s vs %s", tt.v1, tt.v2)
			assert.Equal(t, tt.want, got1, "Compare(%q, %q) == %d, want %d", tt.v1, tt.v2, got1, tt.want)

			// Test symmetry: v2 vs v1
			expectedSymmetric := 0
			if tt.want != 0 {
				expectedSymmetric = -tt.want
			}
			got2, err2 := ver2.Compare(ver1)
			require.NoError(t, err2, "v2.Compare(v1) failed for %s vs %s", tt.v2, tt.v1)
			assert.Equal(t, expectedSymmetric, got2, "Compare(%q, %q) == %d, want %d (symmetric)", tt.v2, tt.v1, got2, expectedSymmetric)

			// Test reflexivity: v1 vs v1
			gotReflexive1, errReflexive1 := ver1.Compare(ver1)
			require.NoError(t, errReflexive1, "v1.Compare(v1) failed for %s", tt.v1)
			assert.Equal(t, 0, gotReflexive1, "Compare(%q, %q) == %d, want 0 (reflexive)", tt.v1, tt.v1, gotReflexive1)
		})
	}
}

func TestRubyVersion_Compare_Errors(t *testing.T) {
	vGem1_0, err := newGemVersion("1.0")
	require.NoError(t, err)

	t.Run("CompareWithNil", func(t *testing.T) {
		_, err := vGem1_0.Compare(nil)
		assert.ErrorIs(t, err, ErrNoVersionProvided)
	})

	t.Run("CompareWithDifferentFormat", func(t *testing.T) {
		// Assuming SemanticFormat is a distinct, incompatible format
		// and that the Format type has a String() method for user-friendly error messages.
		vOther := &Version{Raw: "1.0.0", Format: SemanticFormat}
		_, err := vGem1_0.Compare(vOther)
		require.NoError(t, err)
	})

	t.Run("CompareWithUnknownFormat_ParsableAsGem", func(t *testing.T) {
		vOther := &Version{Raw: "1.1", Format: UnknownFormat} // Parsable as Gem
		res, err := vGem1_0.Compare(vOther)
		assert.NoError(t, err)
		assert.Equal(t, -1, res) // 1.0 < 1.1
	})

	t.Run("CompareWithUnknownFormat_UnparsableAsGem", func(t *testing.T) {
		vOther := &Version{Raw: "invalid..version", Format: UnknownFormat}
		_, err := vGem1_0.Compare(vOther)
		require.Error(t, err)
		require.ErrorContains(t, err, "malformed version number string")
	})
}

func TestRubyVersion_canonical(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    []any
	}{
		// obtained from a simple ruby program like this:
		/*
			require 'rubygems/version'
			v = Gem::Version.new(input)
			v.canonical_segments
		*/
		{"simple ints", "1.2.3", []any{1, 2, 3}},
		{"leading zeros preserved", "0.1.2", []any{0, 1, 2}},
		{"drop intermediate zeros in pre-release", "5.0.0.a1", []any{5, "a", 1}},
		{"preserve intermedia zeros in regular release", "1.0.0.1", []any{1, 0, 0, 1}},
		{"drop trailing zeros", "1.0.0", []any{1}},
		{"alpha version", "1.6.1.a", []any{1, 6, 1, "a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newGemVersion(tt.version)
			require.NoError(t, err)

			if d := cmp.Diff(v.canonical, tt.want); d != "" {
				t.Errorf("canonical mismatch (-want +got):\n%s", d)
			}
		})
	}
}
