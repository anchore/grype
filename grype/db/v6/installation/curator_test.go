package installation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
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

func (m *mockClient) ResolveArchiveURL(_ distribution.Archive) (string, error) {
	return "http://localhost/archive.tar.zst", nil
}

func (m *mockClient) Download(url, dest string, downloadProgress *progress.Manual) (string, error) {
	args := m.Called(url, dest, downloadProgress)
	return args.String(0), args.Error(1)
}

func (m *mockClient) Latest() (*distribution.LatestDocument, error) {
	args := m.Called()
	return args.Get(0).(*distribution.LatestDocument), args.Error(1)
}

func newTestCurator(t *testing.T) curator {
	tempDir := t.TempDir()
	cfg := testConfig()
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

func writeTestDescriptionToDB(t *testing.T, dir string, desc db.Description) string {
	c := db.Config{DBDirPath: dir}
	d, err := db.NewLowLevelDB(c.DBFilePath(), false, true, true)
	require.NoError(t, err)

	if err := d.Where("true").Delete(&db.DBMetadata{}).Error; err != nil {
		t.Fatalf("failed to delete existing DB metadata record: %v", err)
	}

	require.NotEmpty(t, desc.SchemaVersion.Model)
	require.NotEmpty(t, desc.SchemaVersion.String())

	ts := time.Now().UTC()
	instance := &db.DBMetadata{
		BuildTimestamp: &ts,
		Model:          desc.SchemaVersion.Model,
		Revision:       desc.SchemaVersion.Revision,
		Addition:       desc.SchemaVersion.Revision,
	}

	require.NoError(t, d.Create(instance).Error)

	require.NoError(t, d.Exec("VACUUM").Error)

	digest, err := db.CalculateDBDigest(afero.NewOsFs(), c.DBFilePath())
	require.NoError(t, err)

	writeTestImportMetadata(t, afero.NewOsFs(), dir, digest)

	return digest
}

func writeTestImportMetadata(t *testing.T, fs afero.Fs, dir string, checksums string) {
	writeTestImportMetadataWithCustomVersion(t, fs, dir, checksums, schemaver.New(db.ModelVersion, db.Revision, db.Addition).String())
}

func writeTestImportMetadataWithCustomVersion(t *testing.T, fs afero.Fs, dir string, checksums string, ver string) {
	require.NoError(t, fs.MkdirAll(dir, 0755))

	metadataFilePath := filepath.Join(dir, db.ImportMetadataFileName)

	writer, err := afero.NewOsFs().Create(metadataFilePath)
	require.NoError(t, err)
	defer func() { _ = writer.Close() }()
	enc := json.NewEncoder(writer)
	enc.SetIndent("", " ")

	doc := db.ImportMetadata{
		Digest:        checksums,
		ClientVersion: ver,
	}

	require.NoError(t, enc.Encode(doc))
}

func writeTestDB(t *testing.T, fs afero.Fs, dir string) string {
	require.NoError(t, fs.MkdirAll(dir, 0755))

	rw, err := db.NewWriter(db.Config{
		DBDirPath: dir,
	})
	require.NoError(t, err)

	require.NoError(t, rw.SetDBMetadata())
	require.NoError(t, rw.Close())

	doc, err := db.WriteImportMetadata(fs, dir, "source")
	require.NoError(t, err)
	require.NotNil(t, doc)

	return doc.Digest
}

func TestCurator_Update(t *testing.T) {

	t.Run("happy path: successful update", func(t *testing.T) {
		c := setupCuratorForUpdate(t, withWorkingUpdateIntegrations())
		mc := c.client.(*mockClient)
		// nop hydrator, assert error if NOT called
		hydrateCalled := false
		c.hydrator = func(string) error {
			hydrateCalled = true
			return nil
		}

		updated, err := c.Update()

		require.NoError(t, err)
		require.True(t, updated)
		require.FileExists(t, filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName))

		mc.AssertExpectations(t)
		assert.True(t, hydrateCalled, "expected hydrator to be called")
	})

	t.Run("error checking for updates", func(t *testing.T) {
		c := setupCuratorForUpdate(t)
		mc := c.client.(*mockClient)

		mc.On("IsUpdateAvailable", mock.Anything).Return(nil, errors.New("check failed"))

		updated, err := c.Update()

		require.Error(t, err)
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
		// nop hydrator
		c.hydrator = nil

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

		cfg := testConfig()
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

		cfg := testConfig()
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

		cfg := testConfig()
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

func TestCurator_validateAge(t *testing.T) {
	newCurator := func(t *testing.T) curator {
		tempDir := t.TempDir()
		cfg := testConfig()
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

			err := c.validateAge(tt.description)
			tt.wantErr(t, err)
		})
	}
}

func TestCurator_validateIntegrity(t *testing.T) {
	newCurator := func(t *testing.T) (curator, *db.Description) {
		tempDir := t.TempDir()
		cfg := testConfig()
		cfg.DBRootDir = tempDir

		require.NoError(t, os.MkdirAll(cfg.DBDirectoryPath(), 0755))

		sw := setupTestDB(t, cfg.DBDirectoryPath())
		require.NoError(t, sw.SetDBMetadata())
		require.NoError(t, sw.Close())
		s := setupReadOnlyTestDB(t, cfg.DBDirectoryPath())

		// assume that we already have a valid checksum file
		digest, err := db.CalculateDBDigest(afero.NewOsFs(), cfg.DBFilePath())
		require.NoError(t, err)

		writeTestImportMetadata(t, afero.NewOsFs(), cfg.DBDirectoryPath(), digest)

		ci, err := NewCurator(cfg, new(mockClient))
		require.NoError(t, err)

		m, err := s.GetDBMetadata()
		require.NoError(t, err)

		return ci.(curator), db.DescriptionFromMetadata(m)
	}

	t.Run("valid metadata with correct checksum", func(t *testing.T) {
		c, d := newCurator(t)

		digest, err := c.validateIntegrity(d)
		require.NoError(t, err)
		require.NotEmpty(t, digest)
	})

	t.Run("db does not exist", func(t *testing.T) {
		c, d := newCurator(t)

		require.NoError(t, os.Remove(c.config.DBFilePath()))

		_, err := c.validateIntegrity(d)
		require.ErrorContains(t, err, "database does not exist")
	})

	t.Run("import metadata file does not exist", func(t *testing.T) {
		c, d := newCurator(t)
		dbDir := c.config.DBDirectoryPath()
		require.NoError(t, os.Remove(filepath.Join(dbDir, db.ImportMetadataFileName)))
		_, err := c.validateIntegrity(d)
		require.ErrorContains(t, err, "no import metadata")
	})

	t.Run("invalid checksum", func(t *testing.T) {
		c, d := newCurator(t)
		dbDir := c.config.DBDirectoryPath()

		writeTestImportMetadata(t, c.fs, dbDir, "xxh64:invalidchecksum")

		_, err := c.validateIntegrity(d)
		require.ErrorContains(t, err, "bad db checksum")
	})

	t.Run("unsupported database version", func(t *testing.T) {
		c, d := newCurator(t)

		d.SchemaVersion = schemaver.New(db.ModelVersion-1, 0, 0)

		_, err := c.validateIntegrity(d)
		require.ErrorContains(t, err, "unsupported database version")
	})
}

func TestReplaceDB(t *testing.T) {
	cases := []struct {
		name     string
		config   Config
		expected map[string]string // expected file name to content mapping in the DB dir
		init     func(t *testing.T, dir string, dbDir string) afero.Fs
		wantErr  require.ErrorAssertionFunc
		verify   func(t *testing.T, fs afero.Fs, config Config, expected map[string]string)
	}{
		{
			name: "replace non-existent DB",
			config: Config{
				DBRootDir: "/test",
			},
			expected: map[string]string{
				"file.txt": "new content",
			},
			init: func(t *testing.T, dir string, dbDir string) afero.Fs {
				fs := afero.NewBasePathFs(afero.NewOsFs(), t.TempDir())
				require.NoError(t, fs.MkdirAll(dir, 0700))
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "file.txt"), []byte("new content"), 0644))
				return fs
			},
		},
		{
			name: "replace existing DB",
			config: Config{
				DBRootDir: "/test",
			},
			expected: map[string]string{
				"new_file.txt": "new content",
			},
			init: func(t *testing.T, dir string, dbDir string) afero.Fs {
				fs := afero.NewBasePathFs(afero.NewOsFs(), t.TempDir())
				require.NoError(t, fs.MkdirAll(dbDir, 0700))
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dbDir, "old_file.txt"), []byte("old content"), 0644))
				require.NoError(t, fs.MkdirAll(dir, 0700))
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "new_file.txt"), []byte("new content"), 0644))
				return fs
			},
		},
		{
			name: "non-existent parent dir creation",
			config: Config{
				DBRootDir: "/dir/does/not/exist/db3",
			},
			expected: map[string]string{
				"file.txt": "new content",
			},
			init: func(t *testing.T, dir string, dbDir string) afero.Fs {
				fs := afero.NewBasePathFs(afero.NewOsFs(), t.TempDir())
				require.NoError(t, fs.MkdirAll(dir, 0700))
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "file.txt"), []byte("new content"), 0644))
				return fs
			},
		},
		{
			name: "error during rename",
			config: Config{
				DBRootDir: "/test",
			},
			expected: nil, // no files expected since operation fails
			init: func(t *testing.T, dir string, dbDir string) afero.Fs {
				fs := afero.NewBasePathFs(afero.NewOsFs(), t.TempDir())
				require.NoError(t, fs.MkdirAll(dir, 0700))
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "file.txt"), []byte("content"), 0644))
				return afero.NewReadOnlyFs(fs)
			},
			wantErr: require.Error,
			verify: func(t *testing.T, fs afero.Fs, config Config, expected map[string]string) {
				_, err := fs.Stat(config.DBDirectoryPath())
				require.Error(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}
			dbDir := tc.config.DBDirectoryPath()
			candidateDir := "/temp/db"
			fs := tc.init(t, candidateDir, dbDir)

			c := curator{
				fs:     fs,
				config: tc.config,
			}

			err := c.replaceDB(candidateDir)
			tc.wantErr(t, err)
			if tc.verify != nil {
				tc.verify(t, fs, tc.config, tc.expected)
			}
			if err != nil {
				return
			}
			for fileName, expectedContent := range tc.expected {
				filePath := filepath.Join(tc.config.DBDirectoryPath(), fileName)
				actualContent, err := afero.ReadFile(fs, filePath)
				assert.NoError(t, err)
				assert.Equal(t, expectedContent, string(actualContent))
			}
		})
	}
}
func Test_isRehydrationNeeded(t *testing.T) {
	tests := []struct {
		name               string
		currentDBVersion   schemaver.SchemaVer
		hydrationClientVer schemaver.SchemaVer
		currentClientVer   schemaver.SchemaVer
		expectedResult     bool
		expectedErr        string
	}{
		{
			name:             "no database exists",
			currentDBVersion: schemaver.SchemaVer{},
			currentClientVer: schemaver.New(6, 2, 0),
			expectedResult:   false,
		},
		{
			name:             "no import metadata exists",
			currentDBVersion: schemaver.New(6, 0, 0),
			currentClientVer: schemaver.New(6, 2, 0),
			expectedErr:      "unable to read import metadata",
			expectedResult:   false,
		},
		{
			name:               "invalid client version in metadata",
			currentDBVersion:   schemaver.New(6, 0, 0),
			hydrationClientVer: schemaver.SchemaVer{-19, 0, 0},
			currentClientVer:   schemaver.New(6, 2, 0),
			expectedResult:     false,
			expectedErr:        "unable to parse client version from import metadata",
		},
		{
			name:               "rehydration needed",
			currentDBVersion:   schemaver.New(6, 0, 1),
			hydrationClientVer: schemaver.New(6, 0, 0),
			currentClientVer:   schemaver.New(6, 0, 2),
			expectedResult:     true,
		},
		{
			name:               "no rehydration needed - client version equals current client version",
			currentDBVersion:   schemaver.New(6, 0, 0),
			hydrationClientVer: schemaver.New(6, 2, 0),
			currentClientVer:   schemaver.New(6, 2, 0),
			expectedResult:     false,
		},
		{
			name:               "no rehydration needed - client version greater than current client version",
			currentDBVersion:   schemaver.New(6, 0, 0),
			hydrationClientVer: schemaver.New(6, 3, 0),
			currentClientVer:   schemaver.New(6, 2, 0),
			expectedResult:     false,
		},
		{
			// there are cases where new features will result in new columns, thus an old client downloading and hydrating
			// a DB should function, however, when the new client is downloaded it should trigger at least a rehydration
			// of the existing DB (in cases where the new DB is not available for download yet).
			name:               "rehydration needed - we have a new client version, with an old DB version",
			currentDBVersion:   schemaver.New(6, 0, 2),
			hydrationClientVer: schemaver.New(6, 0, 2),
			currentClientVer:   schemaver.New(6, 0, 3),
			expectedResult:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewOsFs()
			testDir := t.TempDir()

			if tt.hydrationClientVer.Model != 0 {
				writeTestImportMetadataWithCustomVersion(t, fs, testDir, "xxh64:something", tt.hydrationClientVer.String())
			}

			var dbVersion *schemaver.SchemaVer
			if tt.currentDBVersion.Model != 0 {
				dbVersion = &tt.currentDBVersion
			}

			result, err := isRehydrationNeeded(fs, testDir, dbVersion, tt.currentClientVer)

			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestCurator_Update_UsesDBRootDirForDownloadTempBase(t *testing.T) {
	c := newTestCurator(t) // This sets up c.fs as afero.NewOsFs() rooted in t.TempDir()
	mc := c.client.(*mockClient)

	// This is the path that the mocked Download method will return.
	// It simulates a temporary directory created by the download client within DBRootDir.
	expectedDownloadedContentPath := filepath.Join(c.config.DBRootDir, "temp-downloaded-db-content-123")

	// Pre-create this directory and make it look like a valid DB source for the hydrator and replaceDB.
	require.NoError(t, c.fs.MkdirAll(expectedDownloadedContentPath, 0755))
	// Write minimal valid DB metadata so that hydration/activation can proceed far enough.
	// Using existing helpers to create a semblance of a DB.
	writeTestDB(t, c.fs, expectedDownloadedContentPath) // This creates a basic DB file and import metadata.

	// Mock client responses
	mc.On("IsUpdateAvailable", mock.Anything).Return(&distribution.Archive{}, nil)
	// CRUCIAL ASSERTION:
	// Verify that Download is called with c.config.DBRootDir as its second argument (baseDirForTemp).
	// It will return the expectedDownloadedContentPath, simulating successful download and extraction.
	mc.On("Download", mock.Anything, c.config.DBRootDir, mock.Anything).Return(expectedDownloadedContentPath, nil)

	hydrateCalled := false
	c.hydrator = func(path string) error {
		// Ensure hydrator is called with the path returned by Download
		assert.Equal(t, expectedDownloadedContentPath, path, "hydrator called with incorrect path")
		hydrateCalled = true
		return nil // Simulate successful hydration
	}

	// Call Update to trigger the download and activation sequence
	updated, err := c.Update()

	// Assertions
	require.NoError(t, err, "Update should succeed")
	require.True(t, updated, "Update should report true")
	mc.AssertExpectations(t) // Verifies that Download was called with the expected arguments
	assert.True(t, hydrateCalled, "expected hydrator to be called")

	// Check if the DB was "activated" (i.e., renamed)
	finalDBPath := c.config.DBDirectoryPath()
	_, err = c.fs.Stat(finalDBPath)
	require.NoError(t, err, "final DB directory should exist after successful update")
	// And the temporary downloaded content path should no longer exist as it was renamed
	_, err = c.fs.Stat(expectedDownloadedContentPath)
	require.True(t, os.IsNotExist(err), "temporary download path should not exist after rename")
}

func TestCurator_Update_CleansUpDownloadDirOnActivationFailure(t *testing.T) {
	c := newTestCurator(t) // Sets up c.fs as afero.NewOsFs() rooted in t.TempDir()
	mc := c.client.(*mockClient)

	// This is the path that the mocked Download method will return.
	// This directory should be cleaned up if activation fails.
	downloadedContentPath := filepath.Join(c.config.DBRootDir, "temp-download-to-be-cleaned-up")

	// Simulate the download client successfully creating this directory.
	require.NoError(t, c.fs.MkdirAll(downloadedContentPath, 0755))
	// Optionally, put a dummy file inside to make the cleanup more tangible.
	require.NoError(t, afero.WriteFile(c.fs, filepath.Join(downloadedContentPath, "dummy_file.txt"), []byte("test data"), 0644))

	// Mock client responses
	mc.On("IsUpdateAvailable", mock.Anything).Return(&distribution.Archive{}, nil)
	// Download is called with DBRootDir as base, and returns the path to the (simulated) downloaded content.
	mc.On("Download", mock.Anything, c.config.DBRootDir, mock.Anything).Return(downloadedContentPath, nil)

	// Configure the hydrator to fail, which will cause c.activate() to fail.
	expectedHydrationError := "simulated hydration failure"
	c.hydrator = func(path string) error {
		assert.Equal(t, downloadedContentPath, path, "hydrator called with incorrect path")
		return errors.New(expectedHydrationError)
	}

	// Call Update, expecting it to fail during activation.
	updated, err := c.Update()

	// Assertions
	require.Error(t, err, "Update should fail due to activation error")
	require.Contains(t, err.Error(), expectedHydrationError, "Error message should reflect hydration failure")
	require.False(t, updated, "Update should report false on failure")
	mc.AssertExpectations(t) // Verifies Download was called as expected.

	// CRUCIAL ASSERTION:
	// Verify that the temporary download directory was cleaned up.
	_, statErr := c.fs.Stat(downloadedContentPath)
	require.True(t, os.IsNotExist(statErr), "expected temporary download directory to be cleaned up after activation failure")
}

// Test for the Import path (URL case) - very similar to the Update tests
func TestCurator_Import_URL_UsesDBRootDirForDownloadTempBaseAndCleansUp(t *testing.T) {
	t.Run("successful import from URL", func(t *testing.T) {
		c := newTestCurator(t)
		mc := c.client.(*mockClient)

		importURL := "http://localhost/some/db.tar.gz"
		expectedDownloadedContentPath := filepath.Join(c.config.DBRootDir, "temp-imported-db-content-url")

		require.NoError(t, c.fs.MkdirAll(expectedDownloadedContentPath, 0755))
		writeTestDB(t, c.fs, expectedDownloadedContentPath)

		mc.On("Download", importURL, c.config.DBRootDir, mock.Anything).Return(expectedDownloadedContentPath, nil)

		hydrateCalled := false
		c.hydrator = func(path string) error {
			assert.Equal(t, expectedDownloadedContentPath, path)
			hydrateCalled = true
			return nil
		}

		err := c.Import(importURL)

		require.NoError(t, err)
		mc.AssertExpectations(t)
		assert.True(t, hydrateCalled)
		_, err = c.fs.Stat(c.config.DBDirectoryPath())
		require.NoError(t, err, "final DB directory should exist")
		_, err = c.fs.Stat(expectedDownloadedContentPath)
		require.True(t, os.IsNotExist(err), "temp import path should not exist after rename")
	})

	t.Run("import from URL fails activation", func(t *testing.T) {
		c := newTestCurator(t)
		mc := c.client.(*mockClient)

		importURL := "http://localhost/some/other/db.tar.gz"
		downloadedContentPath := filepath.Join(c.config.DBRootDir, "temp-imported-to-cleanup-url")

		require.NoError(t, c.fs.MkdirAll(downloadedContentPath, 0755))
		require.NoError(t, afero.WriteFile(c.fs, filepath.Join(downloadedContentPath, "dummy.txt"), []byte("test"), 0644))

		mc.On("Download", importURL, c.config.DBRootDir, mock.Anything).Return(downloadedContentPath, nil)

		expectedHydrationError := "simulated hydration failure for import"
		c.hydrator = func(path string) error {
			return errors.New(expectedHydrationError)
		}

		err := c.Import(importURL)

		require.Error(t, err)
		require.Contains(t, err.Error(), expectedHydrationError)
		mc.AssertExpectations(t)

		_, statErr := c.fs.Stat(downloadedContentPath)
		require.True(t, os.IsNotExist(statErr), "expected temp import directory to be cleaned up")
	})
}

func setupTestDB(t *testing.T, dbDir string) db.ReadWriter {
	s, err := db.NewWriter(db.Config{
		DBDirPath: dbDir,
	})
	require.NoError(t, err)

	return s
}

func setupReadOnlyTestDB(t *testing.T, dbDir string) db.Reader {
	s, err := db.NewReader(db.Config{
		DBDirPath: dbDir,
	})
	require.NoError(t, err)

	return s
}

func testConfig() Config {
	return DefaultConfig(clio.Identification{
		Name: "grype-test",
	})
}
