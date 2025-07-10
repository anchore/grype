package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSet(t *testing.T) {
	tests := []struct {
		name         string
		ignoreFormat bool
		versions     []*Version
		expectedSize int
	}{
		{
			name:         "empty set",
			ignoreFormat: false,
			versions:     nil,
			expectedSize: 0,
		},
		{
			name:         "set with versions",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("2.0.0", SemanticFormat),
			},
			expectedSize: 2,
		},
		{
			name:         "set with duplicate versions ignoring format",
			ignoreFormat: true,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("1.0.0", ApkFormat),
			},
			expectedSize: 1,
		},
		{
			name:         "set with duplicate versions not ignoring format",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("1.0.0", ApkFormat),
			},
			expectedSize: 2,
		},
		{
			name:         "set with nil versions",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				nil,
				New("2.0.0", SemanticFormat),
			},
			expectedSize: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.versions...)
			assert.Equal(t, tt.expectedSize, s.Size())
		})
	}
}

func TestSet_Add(t *testing.T) {
	tests := []struct {
		name               string
		ignoreFormat       bool
		initialVersions    []*Version
		versionsToAdd      []*Version
		expectedSize       int
		expectedContains   *Version
		expectedNotContain *Version
	}{
		{
			name:         "add to empty set",
			ignoreFormat: false,
			versionsToAdd: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize:     1,
			expectedContains: New("1.0.0", SemanticFormat),
		},
		{
			name:         "add nil version",
			ignoreFormat: false,
			versionsToAdd: []*Version{
				nil,
			},
			expectedSize: 0,
		},
		{
			name:         "add duplicate version",
			ignoreFormat: false,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			versionsToAdd: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize:     1,
			expectedContains: New("1.0.0", SemanticFormat),
		},
		{
			name:         "add same version different format with ignoreFormat=true",
			ignoreFormat: true,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			versionsToAdd: []*Version{
				New("1.0.0", ApkFormat),
			},
			expectedSize:     1,
			expectedContains: New("1.0.0", ApkFormat), // latest added wins
		},
		{
			name:         "add same version different format with ignoreFormat=false",
			ignoreFormat: false,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			versionsToAdd: []*Version{
				New("1.0.0", ApkFormat),
			},
			expectedSize:     2,
			expectedContains: New("1.0.0", SemanticFormat),
		},
		{
			name:         "add to set with nil versions map",
			ignoreFormat: false,
			versionsToAdd: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize:     1,
			expectedContains: New("1.0.0", SemanticFormat),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.initialVersions...)
			// for testing nil versions map case
			if tt.name == "add to set with nil versions map" {
				s.versions = nil
			}

			s.Add(tt.versionsToAdd...)

			assert.Equal(t, tt.expectedSize, s.Size())
			if tt.expectedContains != nil {
				assert.True(t, s.Contains(tt.expectedContains))
			}
			if tt.expectedNotContain != nil {
				assert.False(t, s.Contains(tt.expectedNotContain))
			}
		})
	}
}

func TestSet_Remove(t *testing.T) {
	tests := []struct {
		name             string
		ignoreFormat     bool
		initialVersions  []*Version
		versionsToRemove []*Version
		expectedSize     int
		shouldContain    *Version
		shouldNotContain *Version
	}{
		{
			name:         "remove from empty set",
			ignoreFormat: false,
			versionsToRemove: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize: 0,
		},
		{
			name:         "remove existing version",
			ignoreFormat: false,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
				New("2.0.0", SemanticFormat),
			},
			versionsToRemove: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize:     1,
			shouldContain:    New("2.0.0", SemanticFormat),
			shouldNotContain: New("1.0.0", SemanticFormat),
		},
		{
			name:         "remove nil version",
			ignoreFormat: false,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			versionsToRemove: []*Version{
				nil,
			},
			expectedSize:  1,
			shouldContain: New("1.0.0", SemanticFormat),
		},
		{
			name:         "remove non-existing version",
			ignoreFormat: false,
			initialVersions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			versionsToRemove: []*Version{
				New("2.0.0", SemanticFormat),
			},
			expectedSize:  1,
			shouldContain: New("1.0.0", SemanticFormat),
		},
		{
			name:         "remove from set with nil versions map",
			ignoreFormat: false,
			versionsToRemove: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.initialVersions...)
			// for testing nil versions map case
			if tt.name == "remove from set with nil versions map" {
				s.versions = nil
			}

			s.Remove(tt.versionsToRemove...)

			assert.Equal(t, tt.expectedSize, s.Size())
			if tt.shouldContain != nil {
				assert.True(t, s.Contains(tt.shouldContain))
			}
			if tt.shouldNotContain != nil {
				assert.False(t, s.Contains(tt.shouldNotContain))
			}
		})
	}
}

func TestSet_Contains(t *testing.T) {
	tests := []struct {
		name         string
		ignoreFormat bool
		versions     []*Version
		checkVersion *Version
		expected     bool
	}{
		{
			name:         "contains existing version",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("2.0.0", SemanticFormat),
			},
			checkVersion: New("1.0.0", SemanticFormat),
			expected:     true,
		},
		{
			name:         "does not contain non-existing version",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			checkVersion: New("2.0.0", SemanticFormat),
			expected:     false,
		},
		{
			name:         "check nil version",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			checkVersion: nil,
			expected:     false,
		},
		{
			name:         "check version in empty set",
			ignoreFormat: false,
			versions:     nil,
			checkVersion: New("1.0.0", SemanticFormat),
			expected:     false,
		},
		{
			name:         "contains same version different format with ignoreFormat=true",
			ignoreFormat: true,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			checkVersion: New("1.0.0", ApkFormat),
			expected:     true,
		},
		{
			name:         "does not contain same version different format with ignoreFormat=false",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			checkVersion: New("1.0.0", ApkFormat),
			expected:     false,
		},
		{
			name:         "check version with nil versions map",
			ignoreFormat: false,
			versions:     []*Version{},
			checkVersion: New("1.0.0", SemanticFormat),
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.versions...)
			// for testing nil versions map case
			if tt.name == "check version with nil versions map" {
				s.versions = nil
			}

			result := s.Contains(tt.checkVersion)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSet_Values(t *testing.T) {
	tests := []struct {
		name           string
		ignoreFormat   bool
		versions       []*Version
		expectedLength int
		expectedNil    bool
		checkSorted    bool
	}{
		{
			name:           "empty set returns nil",
			ignoreFormat:   false,
			versions:       nil,
			expectedNil:    true,
			expectedLength: 0,
		},
		{
			name:         "set with versions returns sorted list",
			ignoreFormat: false,
			versions: []*Version{
				New("2.0.0", SemanticFormat),
				New("1.0.0", SemanticFormat),
				New("3.0.0", SemanticFormat),
			},
			expectedLength: 3,
			checkSorted:    true,
		},
		{
			name:         "set with nil versions map returns nil",
			ignoreFormat: false,
			versions:     []*Version{},
			expectedNil:  true,
		},
		{
			name:         "set with single version",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
			},
			expectedLength: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.versions...)
			// for testing nil versions map case
			if tt.name == "set with nil versions map returns nil" {
				s.versions = nil
			}

			result := s.Values()

			if tt.expectedNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedLength, len(result))

				if tt.checkSorted && len(result) > 1 {
					// verify sorting - versions should be in ascending order
					for i := 0; i < len(result)-1; i++ {
						cmp, err := result[i].Compare(result[i+1])
						require.NoError(t, err)
						assert.True(t, cmp < 0, "versions should be sorted in ascending order")
					}
				}
			}
		})
	}
}

func TestSet_Size(t *testing.T) {
	tests := []struct {
		name         string
		ignoreFormat bool
		versions     []*Version
		expected     int
	}{
		{
			name:         "empty set size is zero",
			ignoreFormat: false,
			versions:     nil,
			expected:     0,
		},
		{
			name:         "set with versions",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("2.0.0", SemanticFormat),
			},
			expected: 2,
		},
		{
			name:         "set with duplicate versions",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("1.0.0", SemanticFormat),
			},
			expected: 1,
		},
		{
			name:         "set with nil versions map",
			ignoreFormat: false,
			versions:     []*Version{},
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.versions...)
			// for testing nil versions map case
			if tt.name == "set with nil versions map" {
				s.versions = nil
			}

			result := s.Size()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSet_Clear(t *testing.T) {
	tests := []struct {
		name         string
		ignoreFormat bool
		versions     []*Version
	}{
		{
			name:         "clear non-empty set",
			ignoreFormat: false,
			versions: []*Version{
				New("1.0.0", SemanticFormat),
				New("2.0.0", SemanticFormat),
			},
		},
		{
			name:         "clear empty set",
			ignoreFormat: false,
			versions:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.ignoreFormat, tt.versions...)

			originalSize := s.Size()
			s.Clear()

			assert.Equal(t, 0, s.Size())
			assert.NotNil(t, s.versions) // should have empty map, not nil

			// verify all previous versions are gone
			if originalSize > 0 {
				for _, v := range tt.versions {
					if v != nil {
						assert.False(t, s.Contains(v))
					}
				}
			}
		})
	}
}

func TestSet_Integration(t *testing.T) {
	// test combining multiple operations
	s := NewSet(false)

	v1 := New("1.0.0", SemanticFormat)
	v2 := New("2.0.0", SemanticFormat)
	v3 := New("3.0.0", SemanticFormat)

	// add versions
	s.Add(v1, v2, v3)
	assert.Equal(t, 3, s.Size())

	// check contains
	assert.True(t, s.Contains(v1))
	assert.True(t, s.Contains(v2))
	assert.True(t, s.Contains(v3))

	// remove one version
	s.Remove(v2)
	assert.Equal(t, 2, s.Size())
	assert.False(t, s.Contains(v2))

	// get values
	values := s.Values()
	require.Len(t, values, 2)

	// verify sorting
	cmp, err := values[0].Compare(values[1])
	require.NoError(t, err)
	assert.True(t, cmp < 0)

	// clear all
	s.Clear()
	assert.Equal(t, 0, s.Size())
	assert.Nil(t, s.Values())
}
