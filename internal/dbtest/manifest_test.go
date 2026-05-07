package dbtest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestFixtureConfig_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	config := &FixtureConfig{
		AutoGenerate: true,
		Extractions: map[string][]string{
			"debian": {"CVE-2024-1234", "debian:11"},
			"nvd":    {"CVE-2024-1234"},
		},
	}

	err := config.Write(dir)
	require.NoError(t, err)

	// verify file exists
	_, err = os.Stat(filepath.Join(dir, ConfigFilename))
	require.NoError(t, err)

	// read back and compare
	got, err := ReadConfig(dir)
	require.NoError(t, err)

	if d := cmp.Diff(config, got); d != "" {
		t.Errorf("FixtureConfig round-trip mismatch (-want +got):\n%s", d)
	}
}

func TestFixtureLock_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	createdAt := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	regeneratedAt := time.Date(2024, 3, 12, 10, 30, 0, 0, time.UTC)

	lock := &FixtureLock{
		ContentHash:   "a1b2c3d4e5f6g7h8",
		CreatedAt:     createdAt,
		RegeneratedAt: &regeneratedAt,
		Providers: map[string]ProviderState{
			"debian": {
				VunnelVersion: "vunnel@0.55.2.post5+b0ff778",
				Timestamp:     time.Date(2024, 3, 11, 16, 25, 19, 0, time.UTC),
			},
			"nvd": {
				VunnelVersion: "vunnel@0.55.2.post5+b0ff778",
				Timestamp:     time.Date(2024, 3, 10, 8, 0, 0, 0, time.UTC),
			},
		},
	}

	err := lock.Write(dir)
	require.NoError(t, err)

	// verify file exists
	_, err = os.Stat(filepath.Join(dir, LockFilename))
	require.NoError(t, err)

	// read back and compare
	got, err := ReadLock(dir)
	require.NoError(t, err)

	if d := cmp.Diff(lock, got); d != "" {
		t.Errorf("FixtureLock round-trip mismatch (-want +got):\n%s", d)
	}
}

func TestFixtureLock_NoRegeneratedAt(t *testing.T) {
	dir := t.TempDir()

	lock := &FixtureLock{
		ContentHash:   "abc123",
		CreatedAt:     time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		RegeneratedAt: nil, // omitted
		Providers:     map[string]ProviderState{},
	}

	err := lock.Write(dir)
	require.NoError(t, err)

	// verify regenerated_at is omitted from JSON
	data, err := os.ReadFile(filepath.Join(dir, LockFilename))
	require.NoError(t, err)
	require.NotContains(t, string(data), "regenerated_at")

	// read back and verify nil
	got, err := ReadLock(dir)
	require.NoError(t, err)
	require.Nil(t, got.RegeneratedAt)
}

func TestComputeFixtureContentHash(t *testing.T) {
	dir := t.TempDir()

	// create a fixture structure
	providerDir := filepath.Join(dir, "debian", "results")
	require.NoError(t, os.MkdirAll(providerDir, 0755))

	// write some files
	require.NoError(t, os.WriteFile(filepath.Join(providerDir, "CVE-2024-1234.json"), []byte(`{"id": "CVE-2024-1234"}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(providerDir, "listing.xxh64"), []byte("checksum"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "debian", "metadata.json"), []byte(`{"provider": "debian"}`), 0644))

	// compute hash
	hash1, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)
	require.NotEmpty(t, hash1)
	require.Len(t, hash1, 16) // xxh64 hex string

	// compute again - should be deterministic
	hash2, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)

	// modify a file - hash should change
	require.NoError(t, os.WriteFile(filepath.Join(providerDir, "CVE-2024-1234.json"), []byte(`{"id": "CVE-2024-1234", "modified": true}`), 0644))
	hash3, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)
	require.NotEqual(t, hash1, hash3)
}

func TestComputeFixtureContentHash_ExcludesConfigAndLock(t *testing.T) {
	dir := t.TempDir()

	// create minimal fixture
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"test": true}`), 0644))

	// compute hash without config/lock
	hash1, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)

	// add config and lock files
	config := &FixtureConfig{AutoGenerate: true}
	require.NoError(t, config.Write(dir))

	lock := &FixtureLock{ContentHash: "whatever", CreatedAt: time.Now()}
	require.NoError(t, lock.Write(dir))

	// hash should be the same (config/lock excluded)
	hash2, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)
	require.Equal(t, hash1, hash2)
}

func TestGetFixtureStatus(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		want    FixtureStatus
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "no config file",
			setup: func(t *testing.T, dir string) {
				// empty directory
			},
			want: StatusNoConfig,
		},
		{
			name: "manual fixture",
			setup: func(t *testing.T, dir string) {
				config := &FixtureConfig{AutoGenerate: false}
				require.NoError(t, config.Write(dir))
			},
			want: StatusManual,
		},
		{
			name: "reproducible fixture",
			setup: func(t *testing.T, dir string) {
				// create fixture content
				require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte(`test`), 0644))

				// compute hash and create lock
				hash, err := ComputeFixtureContentHash(dir)
				require.NoError(t, err)

				config := &FixtureConfig{AutoGenerate: true}
				require.NoError(t, config.Write(dir))

				lock := &FixtureLock{ContentHash: hash, CreatedAt: time.Now()}
				require.NoError(t, lock.Write(dir))
			},
			want: StatusOK,
		},
		{
			name: "content drift - hash mismatch",
			setup: func(t *testing.T, dir string) {
				// create fixture content
				require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte(`test`), 0644))

				config := &FixtureConfig{AutoGenerate: true}
				require.NoError(t, config.Write(dir))

				// lock with wrong hash
				lock := &FixtureLock{
					ContentHash: "wrong_hash",
					CreatedAt:   time.Now(),
					Providers:   map[string]ProviderState{},
				}
				require.NoError(t, lock.Write(dir))
			},
			want: StatusContentDrift,
		},
		{
			name: "no lock file",
			setup: func(t *testing.T, dir string) {
				config := &FixtureConfig{AutoGenerate: true}
				require.NoError(t, config.Write(dir))
				// no lock file
			},
			want: StatusNoLock,
		},
		{
			name: "config ahead - provider not in lock",
			setup: func(t *testing.T, dir string) {
				// create fixture content
				require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte(`test`), 0644))

				// config with two extractions
				config := &FixtureConfig{
					AutoGenerate: true,
					Extractions: map[string][]string{
						"debian": {"CVE-2024-1234"},
						"nvd":    {"CVE-2024-1234"},
					},
				}
				require.NoError(t, config.Write(dir))

				// compute hash and create lock with only debian provider
				hash, err := ComputeFixtureContentHash(dir)
				require.NoError(t, err)

				lock := &FixtureLock{
					ContentHash: hash,
					CreatedAt:   time.Now(),
					Providers: map[string]ProviderState{
						"debian": {VunnelVersion: "vunnel@test", Timestamp: time.Now()},
						// nvd is missing
					},
				}
				require.NoError(t, lock.Write(dir))
			},
			want: StatusConfigAhead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			dir := t.TempDir()
			tt.setup(t, dir)

			got, err := GetFixtureStatus(dir)
			tt.wantErr(t, err)

			if err != nil {
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}
