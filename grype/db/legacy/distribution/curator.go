package distribution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/hako/durafmt"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/archiver/v3"
	"github.com/anchore/clio"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/store"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

const (
	FileName                = v5.VulnerabilityStoreFileName
	lastUpdateCheckFileName = "last_update_check"
)

type Config struct {
	ID                      clio.Identification
	DBRootDir               string
	ListingURL              string
	CACert                  string
	ValidateByHashOnGet     bool
	ValidateAge             bool
	MaxAllowedBuiltAge      time.Duration
	RequireUpdateCheck      bool
	ListingFileTimeout      time.Duration
	UpdateTimeout           time.Duration
	UpdateCheckMaxFrequency time.Duration
}

type Curator struct {
	fs                      afero.Fs
	listingDownloader       file.Getter
	updateDownloader        file.Getter
	targetSchema            int
	dbDir                   string
	dbPath                  string
	listingURL              string
	validateByHashOnGet     bool
	validateAge             bool
	maxAllowedBuiltAge      time.Duration
	requireUpdateCheck      bool
	updateCheckMaxFrequency time.Duration
}

func NewCurator(cfg Config) (Curator, error) {
	dbDir := path.Join(cfg.DBRootDir, strconv.Itoa(v5.SchemaVersion))

	fs := afero.NewOsFs()
	listingClient, err := defaultHTTPClient(fs, cfg.CACert)
	if err != nil {
		return Curator{}, err
	}
	listingClient.Timeout = cfg.ListingFileTimeout

	dbClient, err := defaultHTTPClient(fs, cfg.CACert)
	if err != nil {
		return Curator{}, err
	}
	dbClient.Timeout = cfg.UpdateTimeout

	return Curator{
		fs:                      fs,
		targetSchema:            v5.SchemaVersion,
		listingDownloader:       file.NewGetter(cfg.ID, listingClient),
		updateDownloader:        file.NewGetter(cfg.ID, dbClient),
		dbDir:                   dbDir,
		dbPath:                  path.Join(dbDir, FileName),
		listingURL:              cfg.ListingURL,
		validateByHashOnGet:     cfg.ValidateByHashOnGet,
		validateAge:             cfg.ValidateAge,
		maxAllowedBuiltAge:      cfg.MaxAllowedBuiltAge,
		requireUpdateCheck:      cfg.RequireUpdateCheck,
		updateCheckMaxFrequency: cfg.UpdateCheckMaxFrequency,
	}, nil
}

func (c Curator) SupportedSchema() int {
	return c.targetSchema
}

func (c *Curator) GetStore() (v5.StoreReader, error) {
	// ensure the DB is ok
	_, err := c.validateIntegrity(c.dbDir)
	if err != nil {
		return nil, fmt.Errorf("vulnerability database is invalid (run db update to correct): %+v", err)
	}

	return store.New(c.dbPath, false)
}

func (c *Curator) Status() Status {
	metadata, err := NewMetadataFromDir(c.fs, c.dbDir)
	if err != nil {
		return Status{
			Err: fmt.Errorf("failed to parse database metadata (%s): %w", c.dbDir, err),
		}
	}
	if metadata == nil {
		return Status{
			Err: fmt.Errorf("database metadata not found at %q", c.dbDir),
		}
	}

	return Status{
		Built:         metadata.Built,
		SchemaVersion: metadata.Version,
		Location:      c.dbDir,
		Checksum:      metadata.Checksum,
		Err:           nil,
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.dbDir)
}

// Update the existing DB, returning an indication if any action was taken.
func (c *Curator) Update() (bool, error) { // nolint: funlen
	if !c.isUpdateCheckAllowed() {
		// we should not notify the user of an update check if the current configuration and state
		// indicates we're should be in a low-pass filter mode (and the check frequency is too high).
		// this should appear to the user as if we never attempted to check for an update at all.
		return false, nil
	}

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

	updateAvailable, metadata, updateEntry, checkErr := c.IsUpdateAvailable()
	if checkErr != nil {
		if c.requireUpdateCheck {
			return false, fmt.Errorf("check for vulnerability database update failed: %w", checkErr)
		}
		log.Warnf("unable to check for vulnerability database update")
		log.Debugf("check for vulnerability update failed: %+v", checkErr)
	}

	if updateAvailable {
		log.Infof("downloading new vulnerability DB")
		err := c.UpdateTo(updateEntry, downloadProgress, importProgress, stage)
		if err != nil {
			return false, fmt.Errorf("unable to update vulnerability database: %w", err)
		}

		// only set the last successful update check if the update was successful
		c.setLastSuccessfulUpdateCheck()

		if metadata != nil {
			log.Infof(
				"updated vulnerability DB from version=%d built=%q to version=%d built=%q",
				metadata.Version,
				metadata.Built.String(),
				updateEntry.Version,
				updateEntry.Built.String(),
			)
			return true, nil
		}

		log.Infof(
			"downloaded new vulnerability DB version=%d built=%q",
			updateEntry.Version,
			updateEntry.Built.String(),
		)
		return true, nil
	}

	// there was no update (or any issue while checking for an update)
	if checkErr == nil {
		c.setLastSuccessfulUpdateCheck()
	}

	stage.Set("no update available")
	return false, nil
}

func (c Curator) isUpdateCheckAllowed() bool {
	if c.updateCheckMaxFrequency == 0 {
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

	return *elapsed > c.updateCheckMaxFrequency
}

func (c Curator) durationSinceUpdateCheck() (*time.Duration, error) {
	// open `$dbDir/last_update_check` file and read the timestamp and do now() - timestamp

	filePath := path.Join(c.dbDir, lastUpdateCheckFileName)

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

func (c Curator) setLastSuccessfulUpdateCheck() {
	// note: we should always assume the DB dir actually exists, otherwise let this operation fail (since having a DB
	// is a prerequisite for a successful update).

	filePath := path.Join(c.dbDir, lastUpdateCheckFileName)
	fh, err := c.fs.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.WithFields("error", err).Trace("unable to write last update check timestamp")
		return
	}

	defer fh.Close()

	_, _ = fmt.Fprintf(fh, "%s", time.Now().UTC().Format(time.RFC3339))
}

// IsUpdateAvailable indicates if there is a new update available as a boolean, and returns the latest listing information
// available for this schema.
func (c *Curator) IsUpdateAvailable() (bool, *Metadata, *ListingEntry, error) {
	log.Debugf("checking for available database updates")

	listing, err := c.ListingFromURL()
	if err != nil {
		return false, nil, nil, err
	}

	updateEntry := listing.BestUpdate(c.targetSchema)
	if updateEntry == nil {
		return false, nil, nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	current, err := NewMetadataFromDir(c.fs, c.dbDir)
	if err != nil {
		return false, nil, nil, fmt.Errorf("current metadata corrupt: %w", err)
	}

	if current.IsSupersededBy(updateEntry) {
		log.Debugf("database update available: %s", updateEntry)
		return true, current, updateEntry, nil
	}
	log.Debugf("no database update available")

	return false, nil, nil, nil
}

// UpdateTo updates the existing DB with the specific other version provided from a listing entry.
func (c *Curator) UpdateTo(listing *ListingEntry, downloadProgress, importProgress *progress.Manual, stage *progress.AtomicStage) error {
	stage.Set("downloading")
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := c.download(listing, downloadProgress)
	if err != nil {
		return err
	}

	stage.Set("validating integrity")
	_, err = c.validateIntegrity(tempDir)
	if err != nil {
		return err
	}

	stage.Set("importing")
	err = c.activate(tempDir)
	if err != nil {
		return err
	}
	stage.Set("updated")
	importProgress.Set(importProgress.Size())
	importProgress.SetCompleted()

	return c.fs.RemoveAll(tempDir)
}

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *Curator) Validate() error {
	metadata, err := c.validateIntegrity(c.dbDir)
	if err != nil {
		return err
	}

	return c.validateStaleness(metadata)
}

// ImportFrom takes a DB archive file and imports it into the final DB location.
func (c *Curator) ImportFrom(dbArchivePath string) error {
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := os.MkdirTemp("", "grype-import")
	if err != nil {
		return fmt.Errorf("unable to create db temp dir: %w", err)
	}

	err = archiver.Unarchive(dbArchivePath, tempDir)
	if err != nil {
		return err
	}

	_, err = c.validateIntegrity(tempDir)
	if err != nil {
		return err
	}

	err = c.activate(tempDir)
	if err != nil {
		return err
	}

	return c.fs.RemoveAll(tempDir)
}

func (c *Curator) download(listing *ListingEntry, downloadProgress *progress.Manual) (string, error) {
	tempDir, err := os.MkdirTemp("", "grype-scratch")
	if err != nil {
		return "", fmt.Errorf("unable to create db temp dir: %w", err)
	}

	// download the db to the temp dir
	url := listing.URL

	// from go-getter, adding a checksum as a query string will validate the payload after download
	// note: the checksum query parameter is not sent to the server
	query := url.Query()
	query.Add("checksum", listing.Checksum)
	url.RawQuery = query.Encode()

	// go-getter will automatically extract all files within the archive to the temp dir
	err = c.updateDownloader.GetToDir(tempDir, listing.URL.String(), downloadProgress)
	if err != nil {
		return "", fmt.Errorf("unable to download db: %w", err)
	}

	return tempDir, nil
}

// validateStaleness ensures the vulnerability database has not passed
// the max allowed age, calculated from the time it was built until now.
func (c *Curator) validateStaleness(m Metadata) error {
	if !c.validateAge {
		return nil
	}

	// built time is defined in UTC,
	// we should compare it against UTC
	now := time.Now().UTC()

	age := now.Sub(m.Built)
	if age > c.maxAllowedBuiltAge {
		return fmt.Errorf("the vulnerability database was built %s ago (max allowed age is %s)", durafmt.ParseShort(age), durafmt.ParseShort(c.maxAllowedBuiltAge))
	}

	return nil
}

func (c *Curator) validateIntegrity(dbDirPath string) (Metadata, error) {
	// check that the disk checksum still matches the db payload
	metadata, err := NewMetadataFromDir(c.fs, dbDirPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to parse database metadata (%s): %w", dbDirPath, err)
	}
	if metadata == nil {
		return Metadata{}, fmt.Errorf("database metadata not found: %s", dbDirPath)
	}

	if c.validateByHashOnGet {
		dbPath := path.Join(dbDirPath, FileName)
		valid, actualHash, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
		if err != nil {
			return Metadata{}, err
		}
		if !valid {
			return Metadata{}, fmt.Errorf("bad db checksum (%s): %q vs %q", dbPath, metadata.Checksum, actualHash)
		}
	}

	if c.targetSchema != metadata.Version {
		return Metadata{}, fmt.Errorf("unsupported database version: have=%d want=%d", metadata.Version, c.targetSchema)
	}

	// TODO: add version checks here to ensure this version of the application can use this database version (relative to what the DB says, not JUST the metadata!)

	return *metadata, nil
}

// activate swaps over the downloaded db to the application directory
func (c *Curator) activate(dbDirPath string) error {
	_, err := c.fs.Stat(c.dbDir)
	if !os.IsNotExist(err) {
		// remove any previous databases
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing database: %w", err)
		}
	}

	// ensure there is an application db directory
	err = c.fs.MkdirAll(c.dbDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	// activate the new db cache
	return file.CopyDir(c.fs, dbDirPath, c.dbDir)
}

// ListingFromURL loads a Listing from a URL.
func (c Curator) ListingFromURL() (Listing, error) {
	tempFile, err := afero.TempFile(c.fs, "", "grype-db-listing")
	if err != nil {
		return Listing{}, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer func() {
		err := c.fs.RemoveAll(tempFile.Name())
		if err != nil {
			log.Errorf("failed to remove file (%s): %w", tempFile.Name(), err)
		}
	}()

	// download the listing file
	err = c.listingDownloader.GetFile(tempFile.Name(), c.listingURL)
	if err != nil {
		return Listing{}, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := NewListingFromFile(c.fs, tempFile.Name())
	if err != nil {
		return Listing{}, err
	}
	return listing, nil
}

func defaultHTTPClient(fs afero.Fs, caCertPath string) (*http.Client, error) {
	httpClient := cleanhttp.DefaultClient()
	httpClient.Timeout = 30 * time.Second
	if caCertPath != "" {
		rootCAs := x509.NewCertPool()

		pemBytes, err := afero.ReadFile(fs, caCertPath)
		if err != nil {
			return nil, fmt.Errorf("unable to configure root CAs for curator: %w", err)
		}
		rootCAs.AppendCertsFromPEM(pemBytes)

		httpClient.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		}
	}
	return httpClient, nil
}
