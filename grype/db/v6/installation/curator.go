package installation

import (
	"fmt"
	"github.com/hashicorp/go-multierror"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/adrg/xdg"
	"github.com/hako/durafmt"
	"github.com/mholt/archiver/v3"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

const lastUpdateCheckFileName = "last_update_check"

type monitor struct {
	*progress.AtomicStage
	downloadProgress *progress.Manual
	importProgress   *progress.Manual
}

type Config struct {
	DBRootDir string

	// validations
	ValidateAge             bool
	ValidateChecksum        bool
	MaxAllowedBuiltAge      time.Duration
	UpdateCheckMaxFrequency time.Duration
}

func DefaultConfig() Config {
	return Config{
		DBRootDir:               filepath.Join(xdg.CacheHome, "grype", "db"),
		ValidateAge:             true,
		ValidateChecksum:        true,
		MaxAllowedBuiltAge:      time.Hour * 24 * 5, // 5 days
		UpdateCheckMaxFrequency: 2 * time.Hour,      // 2 hours
	}
}

func (c Config) DBFilePath() string {
	return path.Join(c.DBDirectoryPath(), db.VulnerabilityDBFileName)
}

func (c Config) DBDirectoryPath() string {
	return path.Join(c.DBRootDir, strconv.Itoa(db.ModelVersion))
}

type curator struct {
	fs     afero.Fs
	client distribution.Client
	config Config
}

func NewCurator(cfg Config, downloader distribution.Client) (db.Curator, error) {
	return curator{
		fs:     afero.NewOsFs(),
		client: downloader,
		config: cfg,
	}, nil
}

func (c curator) Reader() (db.Reader, error) {
	s, err := db.NewReader(
		db.Config{
			DBDirPath: c.config.DBDirectoryPath(),
		},
	)
	if err != nil {
		return nil, err
	}

	return s, c.validate()
}

func (c curator) Status() db.Status {
	dbDir := c.config.DBDirectoryPath()

	d, err := db.ReadDescription(c.config.DBFilePath())
	if err != nil {
		return db.Status{
			Err: err,
		}
	}
	if d == nil {
		return db.Status{
			Err: fmt.Errorf("database not found at %q", dbDir),
		}
	}

	var persistentErr error
	digest, persistentErr := db.CalculateDBDigest(c.config.DBFilePath())

	if valiadateErr := c.validate(); valiadateErr != nil {
		if persistentErr != nil {
			persistentErr = multierror.Append(persistentErr, valiadateErr)
		}
		persistentErr = valiadateErr
	}

	return db.Status{
		Built:         db.Time{Time: d.Built.Time},
		SchemaVersion: d.SchemaVersion.String(),
		Location:      dbDir,
		Checksum:      digest,
		Err:           persistentErr,
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c curator) Delete() error {
	return c.fs.RemoveAll(c.config.DBDirectoryPath())
}

// Update the existing DB, returning an indication if any action was taken.
func (c curator) Update() (bool, error) {
	if !c.isUpdateCheckAllowed() {
		// we should not notify the user of an update check if the current configuration and state
		// indicates we're should be in a low-pass filter mode (and the check frequency is too high).
		// this should appear to the user as if we never attempted to check for an update at all.
		return false, nil
	}

	mon := newMonitor()
	defer mon.SetCompleted()

	current, err := db.ReadDescription(c.config.DBDirectoryPath())
	if err != nil {
		log.WithFields("error", err).Warn("unable to read current database metadata (continuing with update)")
		// downstream any non-existent DB should always be replaced with any best-candidate found
		current = nil
	}

	mon.Set("checking for update")
	update, checkErr := c.client.IsUpdateAvailable(current)
	if checkErr != nil {
		// we want to continue even if we can't check for an update
		log.Warnf("unable to check for vulnerability database update")
		log.WithFields("error", checkErr).Debug("check for vulnerability update failed")
	}

	if update == nil {
		if checkErr == nil {
			// there was no update (or any issue while checking for an update)
			c.setLastSuccessfulUpdateCheck()
		}

		mon.Set("no update available")
		return false, nil
	}

	log.Infof("downloading new vulnerability DB")
	mon.Set("downloading")
	dest, err := c.client.Download(*update, filepath.Dir(c.config.DBRootDir), mon.downloadProgress)
	if err != nil {
		return false, fmt.Errorf("unable to update vulnerability database: %w", err)
	}

	if err := c.activate(dest, mon); err != nil {
		return false, fmt.Errorf("unable to activate new vulnerability database: %w", err)
	}

	// only set the last successful update check if the update was successful
	c.setLastSuccessfulUpdateCheck()

	if current != nil {
		log.WithFields(
			"from", current.Built.String(),
			"to", update.Description.Built.String(),
			"version", update.Description.SchemaVersion,
		).Info("updated vulnerability DB")
		return true, nil
	}

	log.WithFields(
		"version", update.Description.SchemaVersion,
		"built", update.Description.Built.String(),
	).Info("downloaded new vulnerability DB")
	return true, nil
}

func (c curator) isUpdateCheckAllowed() bool {
	if c.config.UpdateCheckMaxFrequency == 0 {
		log.Trace("no max-frequency set for update check")
		return true
	}

	elapsed, err := c.durationSinceUpdateCheck()
	if err != nil {
		// we had an IO error (or similar) trying to read or parse the file, we should not block the update check.
		log.WithFields("error", err).Trace("unable to determine if update check is allowed")
		return true
	}
	if elapsed == nil {
		// there was no last check (this is a first run case), we should not block the update check.
		return true
	}

	return *elapsed > c.config.UpdateCheckMaxFrequency
}

func (c curator) durationSinceUpdateCheck() (*time.Duration, error) {
	// open `$dbDir/last_update_check` file and read the timestamp and do now() - timestamp

	filePath := path.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName)

	if _, err := c.fs.Stat(filePath); os.IsNotExist(err) {
		log.Trace("first-run of DB update")
		return nil, nil
	}

	fh, err := c.fs.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to read last update check timestamp: %w", err)
	}

	defer fh.Close()

	// read and parse rfc3339 timestamp
	var lastCheckStr string
	_, err = fmt.Fscanf(fh, "%s", &lastCheckStr)
	if err != nil {
		return nil, fmt.Errorf("unable to read last update check timestamp: %w", err)
	}

	lastCheck, err := time.Parse(time.RFC3339, lastCheckStr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse last update check timestamp: %w", err)
	}

	if lastCheck.IsZero() {
		return nil, fmt.Errorf("empty update check timestamp")
	}

	elapsed := time.Since(lastCheck)
	return &elapsed, nil
}

func (c curator) setLastSuccessfulUpdateCheck() {
	// note: we should always assume the DB dir actually exists, otherwise let this operation fail (since having a DB
	// is a prerequisite for a successful update).

	filePath := path.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName)
	fh, err := c.fs.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.WithFields("error", err).Trace("unable to write last update check timestamp")
		return
	}

	defer fh.Close()

	_, _ = fmt.Fprintf(fh, "%s", time.Now().UTC().Format(time.RFC3339))
}

// validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c curator) validate() error {
	metadata, err := c.validateIntegrity(c.config.DBFilePath())
	if err != nil {
		return err
	}

	return c.ensureNotStale(metadata)
}

// Import takes a DB archive file and imports it into the final DB location.
func (c curator) Import(dbArchivePath string) error {
	mon := newMonitor()
	mon.Set("unarchiving")
	defer mon.SetCompleted()

	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := os.MkdirTemp(c.config.DBRootDir, fmt.Sprintf("tmp-v%v-import", db.ModelVersion))
	if err != nil {
		return fmt.Errorf("unable to create db temp dir: %w", err)
	}

	err = archiver.Unarchive(dbArchivePath, tempDir)
	if err != nil {
		return err
	}

	mon.downloadProgress.SetCompleted()

	err = c.activate(tempDir, mon)
	if err != nil {
		removeAllOrLog(c.fs, tempDir)
		return err
	}

	return nil
}

// activate swaps over the downloaded db to the application directory
func (c curator) activate(dbDirPath string, mon monitor) error {
	defer mon.importProgress.SetCompleted()

	mon.Set("hashing")

	// overwrite the checksums file with the new checksums
	dbFilePath := filepath.Join(dbDirPath, db.VulnerabilityDBFileName)
	digest, err := db.CalculateDBDigest(dbFilePath)
	if err != nil {
		return err
	}

	checksumsFilePath := filepath.Join(dbDirPath, db.ChecksumFileName)
	if err := afero.WriteFile(c.fs, checksumsFilePath, []byte(digest), 0644); err != nil {
		return err
	}

	mon.Set("activating")

	dbDir := c.config.DBDirectoryPath()
	_, err = c.fs.Stat(dbDir)
	if !os.IsNotExist(err) {
		// remove any previous databases
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing database: %w", err)
		}
	}

	// activate the new db cache by moving the temp dir to final location
	return os.Rename(dbDirPath, dbDir)
}

func (c curator) validateIntegrity(dbFilePath string) (*db.Description, error) {
	// check that the disk checksum still matches the db payload
	metadata, err := db.ReadDescription(dbFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database metadata (%s): %w", dbFilePath, err)
	}
	if metadata == nil {
		return nil, fmt.Errorf("database not found: %s", dbFilePath)
	}

	digest, err := db.CalculateDBDigest(c.config.DBFilePath())
	if err != nil {
		return nil, err
	}

	if c.config.ValidateChecksum {
		valid, actualHash, err := file.ValidateByHash(c.fs, dbFilePath, digest)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("bad db checksum (%s): %q vs %q", dbFilePath, digest, actualHash)
		}
	}

	gotModel, ok := metadata.SchemaVersion.ModelPart()
	if !ok || gotModel != db.ModelVersion {
		return nil, fmt.Errorf("unsupported database version: have=%d want=%d", gotModel, db.ModelVersion)
	}

	return metadata, nil
}

// ensureNotStale ensures the vulnerability database has not passed
// the max allowed age, calculated from the time it was built until now.
func (c curator) ensureNotStale(m *db.Description) error {
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

func removeAllOrLog(fs afero.Fs, dir string) {
	if err := fs.RemoveAll(dir); err != nil {
		log.WithFields("error", err).Warnf("failed to remove path %q", dir)
	}
}

func newMonitor() monitor {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := progress.NewManual(1)
	stage := progress.NewAtomicStage("")
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

	return monitor{
		AtomicStage:      stage,
		downloadProgress: downloadProgress,
		importProgress:   importProgress,
	}
}

func (m monitor) SetCompleted() {
	m.downloadProgress.SetCompleted()
	m.importProgress.SetCompleted()
}
