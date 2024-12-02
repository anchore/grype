package installation

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/internal"
	"github.com/anchore/grype/internal/schemaver"
)

type mockClient struct {
	mock.Mock
}

func (m *mockClient) IsUpdateAvailable(current *db.Description) (*distribution.Archive, error) {
	args := m.Called(current)

	err := args.Error(1)

	if err != nil {
		return nil, err
	}

	return args.Get(0).(*distribution.Archive), nil
}

func (m *mockClient) Download(archive distribution.Archive, dest string, downloadProgress *progress.Manual) (string, error) {
	args := m.Called(archive, dest, downloadProgress)
	return args.String(0), args.Error(1)
}

func (m *mockClient) Latest() (*distribution.LatestDocument, error) {
	args := m.Called()
	return args.Get(0).(*distribution.LatestDocument), args.Error(1)
}

func newTestCurator(t *testing.T) curator {
	tempDir := t.TempDir()
	cfg := DefaultConfig()
	cfg.DBRootDir = tempDir

	ci, err := NewCurator(cfg, new(mockClient))
	require.NoError(t, err)

	c := ci.(curator)
	return c
}

type setupConfig struct {
	workingUpdate bool
}

type setupOption func(*setupConfig)

func withWorkingUpdateIntegrations() setupOption {
	return func(c *setupConfig) {
		c.workingUpdate = true
	}
}

func setupCuratorForUpdate(t *testing.T, opts ...setupOption) curator {
	cfg := setupConfig{}

	for _, o := range opts {
		o(&cfg)
	}

	c := newTestCurator(t)

	dbDir := c.config.DBDirectoryPath()
	stageConfig := Config{DBRootDir: filepath.Join(c.config.DBRootDir, "staged")}
	stageDir := stageConfig.DBDirectoryPath()

	// populate metadata into the downloaded dir
	oldDescription := db.Description{
		SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
		Built:         db.Time{Time: time.Now().Add(-48 * time.Hour)},
	}
	writeTestDB(t, c.fs, dbDir)

	newDescription := oldDescription
	newDescription.Built = db.Time{Time: time.Now()}

	writeTestDB(t, c.fs, stageDir)

	writeTestDescriptionToDB(t, dbDir, oldDescription)
	writeTestDescriptionToDB(t, stageDir, newDescription)

	if cfg.workingUpdate {
		mc := c.client.(*mockClient)

		// ensure the update "works"
		mc.On("IsUpdateAvailable", mock.Anything).Return(&distribution.Archive{}, nil)
		mc.On("Download", mock.Anything, mock.Anything, mock.Anything).Return(stageDir, nil)
	}

	return c
}

func writeTestChecksumsFile(t *testing.T, fs afero.Fs, dir string, checksums string) {
	require.NoError(t, fs.MkdirAll(dir, 0755))

	metadataFilePath := path.Join(dir, db.ChecksumFileName)
	require.NoError(t, afero.WriteFile(fs, metadataFilePath, []byte(checksums), 0644))
}

func writeTestDescriptionToDB(t *testing.T, dir string, desc db.Description) string {
	c := db.Config{DBDirPath: dir}
	d, err := internal.NewDB(c.DBFilePath(), db.Models(), false)
	require.NoError(t, err)

	if err := d.Unscoped().Where("true").Delete(&db.DBMetadata{}).Error; err != nil {
		t.Fatalf("failed to delete existing DB metadata record: %v", err)
	}

	mod, ok := desc.SchemaVersion.ModelPart()
	require.True(t, ok)

	revision, ok := desc.SchemaVersion.RevisionPart()
	require.True(t, ok)

	addition, ok := desc.SchemaVersion.AdditionPart()
	require.True(t, ok)

	ts := time.Now().UTC()
	instance := &db.DBMetadata{
		BuildTimestamp: &ts,
		Model:          mod,
		Revision:       revision,
		Addition:       addition,
	}

	require.NoError(t, d.Create(instance).Error)

	require.NoError(t, d.Exec("VACUUM").Error)

	digest, err := db.CalculateDBDigest(c.DBFilePath())
	require.NoError(t, err)

	// write the checksums file
	writeTestChecksumsFile(t, afero.NewOsFs(), dir, digest)

	return digest
}

func writeTestDB(t *testing.T, fs afero.Fs, dir string) string {
	require.NoError(t, fs.MkdirAll(dir, 0755))

	rw, err := db.NewWriter(db.Config{
		DBDirPath: dir,
	})
	require.NoError(t, err)

	require.NoError(t, rw.SetDBMetadata())
	require.NoError(t, rw.Close())

	checksum, err := db.ReadDBChecksum(dir)

	return checksum
}

func TestCurator_Update(t *testing.T) {

	t.Run("happy path: successful update", func(t *testing.T) {
		c := setupCuratorForUpdate(t, withWorkingUpdateIntegrations())
		mc := c.client.(*mockClient)

		updated, err := c.Update()

		require.NoError(t, err)
		require.True(t, updated)
		require.FileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))

		mc.AssertExpectations(t)
	})

	t.Run("error checking for updates", func(t *testing.T) {
		c := setupCuratorForUpdate(t)
		mc := c.client.(*mockClient)

		mc.On("IsUpdateAvailable", mock.Anything).Return(nil, errors.New("check failed"))

		updated, err := c.Update()

		require.NoError(t, err)
		require.False(t, updated)
		require.NoFileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))

		mc.AssertExpectations(t)
	})

	t.Run("error during download", func(t *testing.T) {
		c := setupCuratorForUpdate(t)
		mc := c.client.(*mockClient)

		mc.On("IsUpdateAvailable", mock.Anything).Return(&distribution.Archive{}, nil)
		mc.On("Download", mock.Anything, mock.Anything, mock.Anything).Return("", errors.New("download failed"))

		updated, err := c.Update()

		require.ErrorContains(t, err, "download failed")
		require.False(t, updated)
		require.NoFileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))

		mc.AssertExpectations(t)
	})

	t.Run("error during activation: cannot move dir", func(t *testing.T) {
		c := setupCuratorForUpdate(t, withWorkingUpdateIntegrations())
		mc := c.client.(*mockClient)

		// simulate not being able to move the staged dir to the db dir
		c.fs = afero.NewReadOnlyFs(c.fs)

		updated, err := c.Update()

		require.ErrorContains(t, err, "operation not permitted")
		require.False(t, updated)
		require.NoFileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))

		mc.AssertExpectations(t)
	})
}

func TestCurator_IsUpdateCheckAllowed(t *testing.T) {

	newCurator := func(t *testing.T) curator {
		tempDir := t.TempDir()

		cfg := DefaultConfig()
		cfg.UpdateCheckMaxFrequency = 10 * time.Minute
		cfg.DBRootDir = tempDir

		ci, err := NewCurator(cfg, nil)
		require.NoError(t, err)

		c := ci.(curator)
		return c
	}

	writeLastCheckContents := func(t *testing.T, cfg Config, contents string) {
		require.NoError(t, os.MkdirAll(cfg.DBDirectoryPath(), 0755))
		p := filepath.Join(cfg.DBDirectoryPath(), lastUpdateCheckFileName)
		err := os.WriteFile(p, []byte(contents), 0644)
		require.NoError(t, err)
	}

	writeLastCheckTime := func(t *testing.T, cfg Config, lastCheckTime time.Time) {
		writeLastCheckContents(t, cfg, lastCheckTime.Format(time.RFC3339))
	}

	t.Run("first run check (no last check file)", func(t *testing.T) {
		c := newCurator(t)
		require.True(t, c.isUpdateCheckAllowed())
	})

	t.Run("check not allowed due to frequency", func(t *testing.T) {
		c := newCurator(t)
		writeLastCheckTime(t, c.config, time.Now().Add(-5*time.Minute))

		require.False(t, c.isUpdateCheckAllowed())
	})

	t.Run("check allowed after the frequency period", func(t *testing.T) {
		c := newCurator(t)
		writeLastCheckTime(t, c.config, time.Now().Add(-20*time.Minute))

		require.True(t, c.isUpdateCheckAllowed())
	})

	t.Run("error reading last check file", func(t *testing.T) {
		c := newCurator(t)

		// simulate a situation where the last check file exists but is corrupted
		writeLastCheckContents(t, c.config, "invalid timestamp")

		allowed := c.isUpdateCheckAllowed()
		require.True(t, allowed) // should return true since an error is encountered
	})

}

func TestCurator_DurationSinceUpdateCheck(t *testing.T) {
	newCurator := func(t *testing.T) curator {
		tempDir := t.TempDir()

		cfg := DefaultConfig()
		cfg.DBRootDir = tempDir

		ci, err := NewCurator(cfg, nil)
		require.NoError(t, err)

		c := ci.(curator)
		return c
	}

	writeLastCheckContents := func(t *testing.T, cfg Config, contents string) {
		require.NoError(t, os.MkdirAll(cfg.DBDirectoryPath(), 0755))
		p := filepath.Join(cfg.DBDirectoryPath(), lastUpdateCheckFileName)
		err := os.WriteFile(p, []byte(contents), 0644)
		require.NoError(t, err)
	}

	t.Run("no last check file", func(t *testing.T) {
		c := newCurator(t)
		elapsed, err := c.durationSinceUpdateCheck()
		require.NoError(t, err)
		require.Nil(t, elapsed) // should be nil since no file exists
	})

	t.Run("valid last check file", func(t *testing.T) {
		c := newCurator(t)
		writeLastCheckContents(t, c.config, time.Now().Add(-5*time.Minute).Format(time.RFC3339))

		elapsed, err := c.durationSinceUpdateCheck()
		require.NoError(t, err)
		require.NotNil(t, elapsed)
		require.True(t, *elapsed >= 5*time.Minute) // should be at least 5 minutes
	})

	t.Run("malformed last check file", func(t *testing.T) {
		c := newCurator(t)
		writeLastCheckContents(t, c.config, "invalid timestamp")

		_, err := c.durationSinceUpdateCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse last update check timestamp")
	})
}

func TestCurator_SetLastSuccessfulUpdateCheck(t *testing.T) {
	newCurator := func(t *testing.T) curator {
		tempDir := t.TempDir()

		cfg := DefaultConfig()
		cfg.DBRootDir = tempDir

		ci, err := NewCurator(cfg, nil)
		require.NoError(t, err)

		c := ci.(curator)

		require.NoError(t, c.fs.MkdirAll(c.config.DBDirectoryPath(), 0755))

		return c
	}

	t.Run("set last successful update check", func(t *testing.T) {
		c := newCurator(t)

		c.setLastSuccessfulUpdateCheck()

		data, err := afero.ReadFile(c.fs, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))
		require.NoError(t, err)

		lastCheckTime, err := time.Parse(time.RFC3339, string(data))
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().UTC(), lastCheckTime, time.Second)
	})

	t.Run("error writing last successful update check", func(t *testing.T) {
		c := newCurator(t)

		// make the file system read-only to simulate a write error
		readonlyFs := afero.NewReadOnlyFs(c.fs)
		c.fs = readonlyFs

		c.setLastSuccessfulUpdateCheck()

		require.NoFileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))
	})

	t.Run("ensure last successful update check file is created", func(t *testing.T) {
		c := newCurator(t)

		c.setLastSuccessfulUpdateCheck()

		require.FileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))
	})
}

func TestCurator_EnsureNotStale(t *testing.T) {
	newCurator := func(t *testing.T) curator {
		tempDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.DBRootDir = tempDir
		cfg.MaxAllowedBuiltAge = 48 * time.Hour // set max age to 48 hours

		ci, err := NewCurator(cfg, new(mockClient))
		require.NoError(t, err)

		return ci.(curator)
	}

	hoursAgo := func(h int) db.Time {
		return db.Time{Time: time.Now().UTC().Add(-time.Duration(h) * time.Hour)}
	}

	tests := []struct {
		name         string
		description  *db.Description
		wantErr      require.ErrorAssertionFunc
		modifyConfig func(*Config)
	}{
		{
			name: "valid metadata within age limit",
			description: &db.Description{
				Built: hoursAgo(24),
			},
		},
		{
			name: "stale metadata exactly at age limit",
			description: &db.Description{
				Built: hoursAgo(48),
			},
			wantErr: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "the vulnerability database was built")
			},
		},
		{
			name: "stale metadata",
			description: &db.Description{
				Built: hoursAgo(50),
			},
			wantErr: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "the vulnerability database was built")
			},
		},
		{
			name:        "no metadata",
			description: nil,
			wantErr: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "no metadata to validate")
			},
		},
		{
			name: "age validation disabled",
			description: &db.Description{
				Built: hoursAgo(50),
			},
			modifyConfig: func(cfg *Config) {
				cfg.ValidateAge = false
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			c := newCurator(t)

			if tt.modifyConfig != nil {
				tt.modifyConfig(&c.config)
			}

			err := c.ensureNotStale(tt.description)
			tt.wantErr(t, err)
		})
	}
}

func TestCurator_ValidateIntegrity(t *testing.T) {
	newCurator := func(t *testing.T) (curator, *db.Description) {
		tempDir := t.TempDir()
		cfg := DefaultConfig()
		cfg.DBRootDir = tempDir

		require.NoError(t, os.MkdirAll(cfg.DBDirectoryPath(), 0755))

		s := setupTestDB(t, cfg.DBDirectoryPath())
		require.NoError(t, s.SetDBMetadata())
		require.NoError(t, s.Close())

		// assume that we already have a valid checksum file
		digest, err := db.CalculateDBDigest(cfg.DBFilePath())
		require.NoError(t, err)

		checksumsFilePath := filepath.Join(cfg.DBDirectoryPath(), db.ChecksumFileName)
		require.NoError(t, os.WriteFile(checksumsFilePath, []byte(digest), 0644))

		ci, err := NewCurator(cfg, new(mockClient))
		require.NoError(t, err)

		m, err := s.GetDBMetadata()
		require.NoError(t, err)

		return ci.(curator), db.DescriptionFromMetadata(m)
	}

	t.Run("valid metadata with correct checksum", func(t *testing.T) {
		c, d := newCurator(t)

		result, digest, err := c.validateIntegrity(d, c.config.DBFilePath(), true)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, digest)
	})

	t.Run("db does not exist", func(t *testing.T) {
		c, d := newCurator(t)

		require.NoError(t, os.Remove(c.config.DBFilePath()))

		_, _, err := c.validateIntegrity(d, c.config.DBFilePath(), true)
		require.ErrorContains(t, err, "database does not exist")
	})

	t.Run("checksum file does not exist", func(t *testing.T) {
		c, d := newCurator(t)
		dbDir := c.config.DBDirectoryPath()
		require.NoError(t, os.Remove(filepath.Join(dbDir, db.ChecksumFileName)))
		_, _, err := c.validateIntegrity(d, c.config.DBFilePath(), true)
		require.ErrorContains(t, err, "no such file or directory")
	})

	t.Run("invalid checksum", func(t *testing.T) {
		c, d := newCurator(t)
		dbDir := c.config.DBDirectoryPath()

		writeTestChecksumsFile(t, c.fs, dbDir, "xxh64:invalidchecksum")

		_, _, err := c.validateIntegrity(d, c.config.DBFilePath(), true)
		require.ErrorContains(t, err, "bad db checksum")
	})

	t.Run("unsupported database version", func(t *testing.T) {
		c, d := newCurator(t)

		d.SchemaVersion = schemaver.New(db.ModelVersion-1, 0, 0)

		_, _, err := c.validateIntegrity(d, c.config.DBFilePath(), true)
		require.ErrorContains(t, err, "unsupported database version")
	})
}

func setupTestDB(t *testing.T, dbDir string) db.ReadWriter {
	s, err := db.NewWriter(db.Config{
		DBDirPath: dbDir,
	})
	require.NoError(t, err)

	return s
}
