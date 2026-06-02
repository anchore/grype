package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadProviderNamesFromRoot(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"alpine", "alma", "rhel"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, name), 0755))
	}
	// regular file at root should be ignored
	require.NoError(t, os.WriteFile(filepath.Join(root, "notes.txt"), []byte("ignored"), 0644))

	got, err := readProviderNamesFromRoot(root)
	require.NoError(t, err)
	sort.Strings(got)
	assert.Equal(t, []string{"alma", "alpine", "rhel"}, got)
}

func TestReadProviderNamesFromRoot_MissingRoot(t *testing.T) {
	_, err := readProviderNamesFromRoot(filepath.Join(t.TempDir(), "does-not-exist"))
	require.Error(t, err)
}

func TestValidateMinRowsCount(t *testing.T) {
	tests := []struct {
		name    string
		minRows int
		counter func() (int64, error)
		want    int64
		wantErr bool
	}{
		{
			name:    "empty count passes when min-rows is -1",
			minRows: -1,
			counter: func() (int64, error) { return 0, nil },
			want:    0,
		},
		{
			name:    "empty count fails when min-rows is 0",
			minRows: 0,
			counter: func() (int64, error) { return 0, nil },
			wantErr: true,
		},
		{
			name:    "count above threshold passes",
			minRows: 12,
			counter: func() (int64, error) { return 13, nil },
			want:    13,
		},
		{
			name:    "count equal to threshold fails (strictly more than)",
			minRows: 13,
			counter: func() (int64, error) { return 13, nil },
			wantErr: true,
		},
		{
			name:    "counter error surfaces",
			counter: func() (int64, error) { return 0, fmt.Errorf("boom") },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := validateMinRowsCount(tt.minRows, tt.counter)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, count)
		})
	}
}
