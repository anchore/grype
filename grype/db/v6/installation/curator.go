package installation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/hako/durafmt"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/archiver/v3"
	"github.com/anchore/clio"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/schemaver"
)

const lastUpdateCheckFileName = "last_update_check"

type monitor struct {
	*progress.AtomicStage
	downloadProgress completionMonitor
	importProgress   completionMonitor
	hydrateProgress  completionMonitor
}

type Config struct {
	DBRootDir string
	Debug     bool

	// validations
	ValidateAge             bool
	ValidateChecksum        bool
	MaxAllowedBuiltAge      time.Duration
	UpdateCheckMaxFrequency time.Duration
}

func DefaultConfig(id clio.Identification) Config {
	return Config{
		DBRootDir:               filepath.Join(xdg.CacheHome, id.Name, "db"),
		ValidateAge:             true,
		ValidateChecksum:        true,
		MaxAllowedBuiltAge:      time.Hour * 24 * 5, // 5 days
		UpdateCheckMaxFrequency: 2 * time.Hour,      // 2 hours
	}
}

func (c Config) DBFilePath() string {
	return filepath.Join(c.DBDirectoryPath(), db.VulnerabilityDBFileName)
}

func (c Config) DBDirectoryPath() string {
	return filepath.Join(c.DBRootDir, strconv.Itoa(db.ModelVersion))
}

type curator struct {
	fs       afero.Fs
	client   distribution.Client
	config   Config
	hydrator func(string) error
}

func NewCurator(cfg Config, downloader distribution.Client) (db.Curator, error) {
	return curator{
		fs:       afero.NewOsFs(),
		client:   downloader,
		config:   cfg,
		hydrator: db.Hydrater(),
	}, nil
}

func (c curator) Reader() (db.Reader, error) {
	s, err := db.NewReader(
		db.Config{
			DBDirPath: c.config.DBDirectoryPath(),
			Debug:     c.config.Debug,
		},
	)
	if err != nil {
		return nil, err
	}

	m, err := s.GetDBMetadata()
	if err != nil {
		return nil, fmt.Errorf("unable to get vulnerability store metadata: %w", err)
	}

	var currentDBSchemaVersion *schemaver.SchemaVer
	if m != nil {
		v := schemaver.New(m.Model, m.Revision, m.Addition)
		currentDBSchemaVersion = &v
	}

	doRehydrate, err := isRehydrationNeeded(c.fs, c.config.DBDirectoryPath(), currentDBSchemaVersion, schemaver.New(db.ModelVersion, db.Revision, db.Addition))
	if err != nil {
		return nil, err
	}
	if doRehydrate {
		if err = s.Close(); err != nil {
			// DB connection may be in an inconsistent state -- we cannot continue
			return nil, fmt.Errorf("unable to close reader before rehydration: %w", err)
		}
		mon := newMonitor()

		mon.Set("rehydrating DB")
		log.Info("rehydrating DB")

		// we're not changing the source of the DB, so we just want to use any existing value.
		// if the source is empty/does not exist, it will be empty in the new metadata.
		var source string
		im, err := db.ReadImportMetadata(c.fs, c.config.DBDirectoryPath())
		if err == nil && im != nil {
			// ignore errors, as this is just a best-effort to get the source
			source = im.Source
		}

		// this is a condition where an old client imported a DB with additional capabilities than it can handle at hydration.
		// this could lead to missing indexes and degraded performance now that a newer client is running (that can handle these capabilities).
		// the only sensible thing to do is to rehydrate the existing DB to ensure indexes are up-to-date with the current client's capabilities.
		if err := c.hydrate(c.config.DBDirectoryPath(), source, mon); err != nil {
			log.WithFields("error", err).Warn("unable to rehydrate DB")
		}
		mon.Set("rehydrated")
		mon.SetCompleted()

		s, err = db.NewReader(
			db.Config{
				DBDirPath: c.config.DBDirectoryPath(),
				Debug:     c.config.Debug,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new reader after rehydration: %w", err)
		}
	}

	return s, nil
}

func (c curator) Status() vulnerability.ProviderStatus {
	dbFile := c.config.DBFilePath()
	d, validateErr := db.ReadDescription(dbFile)
	if validateErr != nil {
		return vulnerability.ProviderStatus{
			Path:  dbFile,
			Error: validateErr,
		}
	}
	if d == nil {
		return vulnerability.ProviderStatus{
			Path:  dbFile,
			Error: fmt.Errorf("database not found at %q", dbFile),
		}
	}

	validateErr = c.validateAge(d)
	_, checksumErr := c.validateIntegrity(d)
	if checksumErr != nil && c.config.ValidateChecksum {
		if validateErr != nil {
			validateErr = errors.Join(validateErr, checksumErr)
		} else {
			validateErr = checksumErr
		}
	}

	var source string
	im, readErr := db.ReadImportMetadata(c.fs, c.config.DBDirectoryPath())
	if readErr == nil && im != nil {
		// only make a best-effort to get the source
		source = im.Source
	}

	return vulnerability.ProviderStatus{
		Built:         d.Built.Time,
		SchemaVersion: d.SchemaVersion.String(),
		From:          source,
		Path:          dbFile,
		Error:         validateErr,
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c curator) Delete() error {
	return c.fs.RemoveAll(c.config.DBDirectoryPath())
}

// Update the existing DB, returning an indication if any action was taken.
func (c curator) Update() (bool, error) {
	current, err := db.ReadDescription(c.config.DBFilePath())
	if err != nil {
		// we should not warn if the DB does not exist, as this is a common first-run case... but other cases we
		// may care about, so warn in those cases.
		if !errors.Is(err, db.ErrDBDoesNotExist) {
			log.WithFields("error", err).Warn("unable to read current database metadata; continuing with update")
		}
		// downstream any non-existent DB should always be replaced with any best-candidate found
		current = nil
	} else {
		err = c.validateAge(current)
		if err != nil {
			// even if we are not allowed to check for an update, we should still attempt to update the DB if it is invalid
			log.WithFields("error", err).Warn("current database is invalid")
			current = nil
		}
	}

	if current != nil && !c.isUpdateCheckAllowed() {
		// we should not notify the user of an update check if the current configuration and state
		// indicates we are in a low-pass filter mode and the check frequency is too high.
		// this should appear to the user as if we never attempted to check for an update at all.
		return false, nil
	}

	update, err := c.update(current)
	if err != nil {
		return false, err
	}

	if update == nil {
		return false, nil
	}

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
	).Info("installed new vulnerability DB")
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

func (c curator) update(current *db.Description) (*distribution.Archive, error) {
	mon := newMonitor()
	defer mon.SetCompleted()
	startTime := time.Now()

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
		return nil, checkErr
	}

	log.Info("downloading new vulnerability DB")
	mon.Set("downloading")
	url, err := c.client.ResolveArchiveURL(*update)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve vulnerability DB URL: %w", err)
	}

	// Ensure parent of DBRootDir exists for the download client to create a temp dir within DBRootDir
	// This might be redundant if DBRootDir must already exist, but good for safety.
	if err := os.MkdirAll(c.config.DBRootDir, 0o700); err != nil {
		return nil, fmt.Errorf("unable to create db root dir %s for download: %w", c.config.DBRootDir, err)
	}

	dest, err := c.client.Download(url, c.config.DBRootDir, mon.downloadProgress.Manual)
	if err != nil {
		return nil, fmt.Errorf("unable to update vulnerability database: %w", err)
	}

	log.WithFields("url", url, "time", time.Since(startTime)).Info("downloaded vulnerability DB")

	mon.downloadProgress.SetCompleted()
	if err = c.activate(dest, url, mon); err != nil {
		log.Warnf("Failed to activate downloaded database from %s, attempting cleanup of temporary download directory.", dest)
		removeAllOrLog(c.fs, dest)
		return nil, fmt.Errorf("unable to activate new vulnerability database: %w", err)
	}

	mon.Set("updated")

	// only set the last successful update check if the update was successful
	c.setLastSuccessfulUpdateCheck()

	return update, nil
}

func isRehydrationNeeded(fs afero.Fs, dirPath string, currentDBVersion *schemaver.SchemaVer, currentClientVersion schemaver.SchemaVer) (bool, error) {
	if currentDBVersion == nil {
		// there is no DB to rehydrate
		return false, nil
	}

	importMetadata, err := db.ReadImportMetadata(fs, dirPath)
	if err != nil {
		return false, fmt.Errorf("unable to read import metadata: %w", err)
	}

	clientHydrationVersion, err := schemaver.Parse(importMetadata.ClientVersion)
	if err != nil {
		return false, fmt.Errorf("unable to parse client version from import metadata: %w", err)
	}

	hydratedWithOldClient := clientHydrationVersion.LessThanOrEqualTo(*currentDBVersion)
	haveNewerClient := clientHydrationVersion.LessThan(currentClientVersion)
	doRehydrate := hydratedWithOldClient && haveNewerClient

	msg := "DB rehydration not needed"
	if doRehydrate {
		msg = "DB rehydration needed"
	}

	log.WithFields("clientHydrationVersion", clientHydrationVersion, "currentDBVersion", currentDBVersion, "currentClientVersion", currentClientVersion).Trace(msg)

	if doRehydrate {
		// this is a condition where an old client imported a DB with additional capabilities than it can handle at hydration.
		// this could lead to missing indexes and degraded performance now that a newer client is running (that can handle these capabilities).
		// the only sensible thing to do is to rehydrate the existing DB to ensure indexes are up-to-date with the current client's capabilities.
		return true, nil
	}

	return false, nil
}

func (c curator) durationSinceUpdateCheck() (*time.Duration, error) {
	// open `$dbDir/last_update_check` file and read the timestamp and do now() - timestamp

	filePath := filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName)

	if _, err := c.fs.Stat(filePath); os.IsNotExist(err) {
		log.Trace("first-run of DB update")
		return nil, nil
	}

	fh, err := c.fs.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to read last update check timestamp: %w", err)
	}

	defer log.CloseAndLogError(fh, filePath)

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

	filePath := filepath.Join(c.config.DBDirectoryPath(), lastUpdateCheckFileName)
	fh, err := c.fs.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		log.WithFields("error", err).Trace("unable to write last update check timestamp")
		return
	}

	defer log.CloseAndLogError(fh, filePath)

	_, _ = fmt.Fprintf(fh, "%s", time.Now().UTC().Format(time.RFC3339))
}

// Import takes a DB file path, archive file path, or URL and imports it into the final DB location.
func (c curator) Import(reference string) error {
	mon := newMonitor()
	mon.Set("preparing")
	defer mon.SetCompleted()

	if err := os.MkdirAll(c.config.DBRootDir, 0o700); err != nil {
		return fmt.Errorf("unable to create db root dir: %w", err)
	}

	var tempDir, url string
	if isURL(reference) {
		log.Info("downloading new vulnerability DB")
		mon.Set("downloading")
		var err error

		tempDir, err = c.client.Download(reference, c.config.DBRootDir, mon.downloadProgress.Manual)
		if err != nil {
			return fmt.Errorf("unable to update vulnerability database: %w", err)
		}

		url = reference
	} else {
		// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
		var err error
		tempDir, err = os.MkdirTemp(c.config.DBRootDir, fmt.Sprintf("tmp-v%v-import", db.ModelVersion))
		if err != nil {
			return fmt.Errorf("unable to create db import temp dir: %w", err)
		}

		url = "manual import"

		if strings.HasSuffix(reference, ".db") {
			// this is a raw DB file, copy it to the temp dir
			log.Trace("copying DB")
			if err := file.CopyFile(afero.NewOsFs(), reference, filepath.Join(tempDir, db.VulnerabilityDBFileName)); err != nil {
				return fmt.Errorf("unable to copy DB file: %w", err)
			}
		} else {
			// assume it is an archive
			log.Info("unarchiving DB")
			err := archiver.Unarchive(reference, tempDir)
			if err != nil {
				return err
			}
		}
	}

	mon.downloadProgress.SetCompleted()

	if err := c.activate(tempDir, url, mon); err != nil {
		removeAllOrLog(c.fs, tempDir)
		return err
	}

	mon.Set("imported")

	return nil
}

var urlPrefixPattern = regexp.MustCompile("^[a-zA-Z]+://")

func isURL(reference string) bool {
	return urlPrefixPattern.MatchString(reference)
}

// activate swaps over the downloaded db to the application directory, calculates the checksum, and records the checksums to a file.
func (c curator) activate(dbDirPath, url string, mon monitor) error {
	defer mon.SetCompleted()

	startTime := time.Now()
	if err := c.hydrate(dbDirPath, url, mon); err != nil {
		return fmt.Errorf("failed to hydrate database: %w", err)
	}

	log.WithFields("time", time.Since(startTime)).Trace("hydrated db")
	startTime = time.Now()
	defer func() { log.WithFields("time", time.Since(startTime)).Trace("replaced db") }()

	mon.Set("activating")

	return c.replaceDB(dbDirPath)
}

func (c curator) hydrate(dbDirPath, from string, mon monitor) error {
	if c.hydrator != nil {
		mon.Set("hydrating")
		if err := c.hydrator(dbDirPath); err != nil {
			return err
		}
	}
	mon.hydrateProgress.SetCompleted()

	mon.Set("hashing")

	doc, err := db.WriteImportMetadata(c.fs, dbDirPath, from)
	if err != nil {
		return fmt.Errorf("failed to write checksums file: %w", err)
	}

	log.WithFields("digest", doc.Digest).Trace("captured DB digest")

	return nil
}

// replaceDB swaps over to using the given path.
func (c curator) replaceDB(dbDirPath string) error {
	dbDir := c.config.DBDirectoryPath()
	_, err := c.fs.Stat(dbDir)
	if !os.IsNotExist(err) {
		// remove any previous databases
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing database: %w", err)
		}
	}

	// ensure parent db directory exists
	if err = c.fs.MkdirAll(filepath.Dir(dbDir), 0o700); err != nil {
		return fmt.Errorf("unable to create db parent directory: %w", err)
	}

	// activate the new db cache by moving the temp dir to final location
	// the rename should be safe because the temp dir is under GRYPE_DB_CACHE_DIR
	// and so on the same filesystem as the final location
	err = c.fs.Rename(dbDirPath, dbDir)
	if err != nil {
		err = fmt.Errorf("failed to move database directory to activate: %w", err)
	}
	log.WithFields("from", dbDirPath, "to", dbDir, "error", err).Debug("moved database directory to activate")
	return err
}

// validateIntegrity checks that the disk checksum still matches the db payload
func (c curator) validateIntegrity(description *db.Description) (string, error) {
	dbFilePath := c.config.DBFilePath()

	// check that the disk checksum still matches the db payload
	if description == nil {
		return "", fmt.Errorf("database not found: %s", dbFilePath)
	}

	if description.SchemaVersion.Model != db.ModelVersion {
		return "", fmt.Errorf("unsupported database version: have=%d want=%d", description.SchemaVersion.Model, db.ModelVersion)
	}

	if _, err := c.fs.Stat(dbFilePath); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("database does not exist: %s", dbFilePath)
		}
		return "", fmt.Errorf("failed to access database file: %w", err)
	}

	importMetadata, err := db.ReadImportMetadata(c.fs, filepath.Dir(dbFilePath))
	if err != nil {
		return "", err
	}

	valid, actualHash, err := file.ValidateByHash(c.fs, dbFilePath, importMetadata.Digest)
	if err != nil {
		return actualHash, err
	}
	if !valid {
		return actualHash, fmt.Errorf("bad db checksum (%s): %q vs %q", dbFilePath, importMetadata.Digest, actualHash)
	}

	return actualHash, nil
}

// validateAge ensures the vulnerability database has not passed
// the max allowed age, calculated from the time it was built until now.
func (c curator) validateAge(m *db.Description) error {
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
	hydrateProgress := progress.NewManual(1)
	aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, hydrateProgress, importProgress)

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
		downloadProgress: completionMonitor{downloadProgress},
		importProgress:   completionMonitor{importProgress},
		hydrateProgress:  completionMonitor{hydrateProgress},
	}
}

func (m monitor) SetCompleted() {
	m.downloadProgress.SetCompleted()
	m.importProgress.SetCompleted()
	m.hydrateProgress.SetCompleted()
}

// completionMonitor is a progressable that, when SetComplete() is called, will set the progress to the total size
type completionMonitor struct {
	*progress.Manual
}

func (m completionMonitor) SetCompleted() {
	m.Set(m.Size())
	m.Manual.SetCompleted()
}
