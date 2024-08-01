package installation

import (
	"fmt"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/hako/durafmt"
	"github.com/mholt/archiver/v3"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"os"
	"path"
	"strconv"
	"time"
)

const (
	DatabaseFileName = "vulnerability.db"
)

type Config struct {
	DBRootDir          string
	ValidateAge        bool
	ValidateChecksum   bool
	MaxAllowedBuiltAge time.Duration
}

type DatabaseCurator struct {
	fs     afero.Fs
	client distribution.Client
	config Config
}

func NewDatabaseCurator(cfg Config, downloader distribution.Client) (DatabaseCurator, error) {
	return DatabaseCurator{
		fs:     afero.NewOsFs(),
		client: downloader,
		config: cfg,
	}, nil
}

func (c DatabaseCurator) dbFilePath() string {
	return path.Join(c.dbDirectoryPath(), DatabaseFileName)
}

func (c DatabaseCurator) dbDirectoryPath() string {
	return path.Join(c.config.DBRootDir, strconv.Itoa(grypeDB.SchemaVersion))
}

func (c *DatabaseCurator) GetStore() (grypeDB.StoreReader, error) {
	s, err := grypeDB.New(
		grypeDB.StoreConfig{
			DBDirPath: c.dbDirectoryPath(),
			Overwrite: false,
		},
	)
	if err != nil {
		return nil, err
	}

	return s, c.Validate()
}

func (c *DatabaseCurator) Status() Status {
	dbDir := c.dbDirectoryPath()

	d, err := distribution.ReadDatabaseDescription(c.fs, dbDir)
	if err != nil {
		return Status{
			Err: fmt.Errorf("failed to parse database metadata (%s): %w", dbDir, err),
		}
	}
	if d == nil {
		return Status{
			Err: fmt.Errorf("database metadata not found at %q", dbDir),
		}
	}

	return Status{
		Built:         d.Built.Time,
		SchemaVersion: *d.SchemaVersion,
		Location:      dbDir,
		Checksum:      d.Checksum,
		Err:           c.Validate(),
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c *DatabaseCurator) Delete() error {
	return c.fs.RemoveAll(c.dbDirectoryPath())
}

// Update the existing DB, returning an indication if any action was taken.
func (c *DatabaseCurator) Update() (bool, error) {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := progress.NewManual(1)
	stage := progress.NewAtomicStage("checking for update")
	downloadProgress := progress.NewManual(1)
	aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, importProgress)

	bus.Publish(partybus.Event{
		Type: event.UpdateVulnerabilityDatabase,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: progress.Progressable(aggregateProgress),
		}),
	})

	defer downloadProgress.SetCompleted()
	defer importProgress.SetCompleted()

	current, err := distribution.ReadDatabaseDescription(c.fs, c.dbDirectoryPath())
	if err != nil {
		return false, fmt.Errorf("unable to read current database metadata: %w", err)
	}

	stage.Set("checking for update")
	updateEntry, err := c.client.IsUpdateAvailable(current)
	if err != nil {
		// we want to continue if possible even if we can't check for an update
		log.Warnf("unable to check for vulnerability database update")
		log.Debugf("check for vulnerability update failed: %+v", err)
	}

	if updateEntry == nil {
		stage.Set("no update available")
		return false, nil
	}

	log.Infof("downloading new vulnerability DB")
	stage.Set("downloading")
	dest, err := c.client.Download(updateEntry, downloadProgress)
	if err != nil {
		return false, fmt.Errorf("unable to update vulnerability database: %w", err)
	}

	if err := c.activate(dest, importProgress, stage); err != nil {
		return false, fmt.Errorf("unable to activate new vulnerability database: %w", err)
	}

	if current != nil {
		log.WithFields().Infof(
			"updated vulnerability DB from version=%d built=%q to version=%d built=%q",
			current.SchemaVersion,
			current.Built.String(),
			updateEntry.Description.SchemaVersion,
			updateEntry.Description.Built.String(),
		)
		return true, nil
	}

	log.Infof(
		"downloaded new vulnerability DB version=%d built=%q",
		updateEntry.Description.SchemaVersion,
		updateEntry.Description.Built.String(),
	)
	return true, nil
}

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *DatabaseCurator) Validate() error {
	metadata, err := c.validateIntegrity(c.dbDirectoryPath())
	if err != nil {
		return err
	}

	return c.ensureNotStale(metadata)
}

// ImportFrom takes a DB archive file and imports it into the final DB location.
func (c *DatabaseCurator) ImportFrom(dbArchivePath string) error {
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := os.MkdirTemp("", "grype-import")
	if err != nil {
		return fmt.Errorf("unable to create db temp dir: %w", err)
	}

	err = archiver.Unarchive(dbArchivePath, tempDir)
	if err != nil {
		return err
	}

	err = c.activate(tempDir, nil, nil)
	if err != nil {
		return err
	}

	return c.fs.RemoveAll(tempDir)
}

// activate swaps over the downloaded db to the application directory
func (c *DatabaseCurator) activate(dbDirPath string, importProgress *progress.Manual, stage *progress.AtomicStage) error {
	if importProgress != nil {
		defer importProgress.SetCompleted()
	}
	if stage != nil {
		stage.Set("validating DB integrity")
	}
	if _, err := c.validateIntegrity(dbDirPath); err != nil {
		return err
	}

	if stage != nil {
		stage.Set("activating")
	}

	dbDir := c.dbDirectoryPath()
	_, err := c.fs.Stat(dbDir)
	if !os.IsNotExist(err) {
		// remove any previous databases
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing database: %w", err)
		}
	}

	// ensure there is an application db directory
	err = c.fs.MkdirAll(dbDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	// activate the new db cache
	return file.CopyDir(c.fs, dbDirPath, dbDir)
}

func (c *DatabaseCurator) validateIntegrity(dbDirPath string) (*distribution.DatabaseDescription, error) {
	// check that the disk checksum still matches the db payload
	metadata, err := distribution.ReadDatabaseDescription(c.fs, dbDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database metadata (%s): %w", dbDirPath, err)
	}
	if metadata == nil {
		return nil, fmt.Errorf("database metadata not found: %s", dbDirPath)
	}

	if c.config.ValidateChecksum {
		dbPath := path.Join(dbDirPath, DatabaseFileName)
		valid, actualHash, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("bad db checksum (%s): %q vs %q", dbPath, metadata.Checksum, actualHash)
		}
	}

	if *metadata.SchemaVersion != grypeDB.SchemaVersion {
		return nil, fmt.Errorf("unsupported database version: have=%d want=%d", metadata.SchemaVersion, grypeDB.SchemaVersion)
	}

	// TODO: add version checks here to ensure this version of the application can use this database version (relative to what the DB says, not JUST the metadata!)

	return metadata, nil
}

// ensureNotStale ensures the vulnerability database has not passed
// the max allowed age, calculated from the time it was built until now.
func (c *DatabaseCurator) ensureNotStale(m *distribution.DatabaseDescription) error {
	if m == nil {
		return fmt.Errorf("no metadata to validate")
	}

	if !c.config.ValidateAge {
		return nil
	}

	// built time is defined in UTC,
	// we should compare it against UTC
	now := time.Now().UTC()

	age := now.Sub(m.Built.Time)
	if age > c.config.MaxAllowedBuiltAge {
		return fmt.Errorf("the vulnerability database was built %s ago (max allowed age is %s)", durafmt.ParseShort(age), durafmt.ParseShort(c.config.MaxAllowedBuiltAge))
	}

	return nil
}
