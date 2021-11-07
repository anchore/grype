package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	"github.com/anchore/grype-db/pkg/curation"
	grypeDB "github.com/anchore/grype-db/pkg/db/v3"
	"github.com/anchore/grype-db/pkg/db/v3/reader"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

const (
	FileName = grypeDB.VulnerabilityStoreFileName
)

type Config struct {
	DBRootDir           string
	ListingURL          string
	ValidateByHashOnGet bool
}

type Curator struct {
	fs                  afero.Fs
	downloader          file.Getter
	targetSchema        int
	dbDir               string
	dbPath              string
	listingURL          string
	validateByHashOnGet bool
}

func NewCurator(cfg Config) Curator {
	dbDir := path.Join(cfg.DBRootDir, strconv.Itoa(vulnerability.SchemaVersion))
	return Curator{
		fs:                  afero.NewOsFs(),
		targetSchema:        vulnerability.SchemaVersion,
		downloader:          file.NewGetter(nil),
		dbDir:               dbDir,
		dbPath:              path.Join(dbDir, FileName),
		listingURL:          cfg.ListingURL,
		validateByHashOnGet: cfg.ValidateByHashOnGet,
	}
}

func (c *Curator) GetStore() (*reader.Reader, error) {
	// ensure the DB is ok
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("vulnerability database is corrupt (run db update to correct): %+v", err)
	}

	s, _, err := reader.New(c.dbPath)
	return s, err
}

func (c *Curator) Status() Status {
	metadata, err := curation.NewMetadataFromDir(c.fs, c.dbDir)
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
		Err:           c.Validate(),
	}
}

// Delete removes the DB and metadata file for this specific schema.
func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.dbDir)
}

// Update the existing DB, returning an indication if any action was taken.
func (c *Curator) Update() (bool, error) {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := &progress.Manual{
		Total: 1,
	}
	stage := &progress.Stage{
		Current: "checking for update",
	}
	downloadProgress := &progress.Manual{
		Total: 1,
	}
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

	updateAvailable, updateEntry, err := c.IsUpdateAvailable()
	if err != nil {
		// we want to continue if possible even if we can't check for an update
		log.Infof("unable to check for vulnerability database update")
		log.Debugf("check for vulnerability update failed: %+v", err)
	}
	if updateAvailable {
		log.Infof("Downloading new vulnerability DB")
		err = c.UpdateTo(updateEntry, downloadProgress, importProgress, stage)
		if err != nil {
			return false, fmt.Errorf("unable to update vulnerability database: %w", err)
		}
		log.Infof("Updated vulnerability DB to version=%d built=%q", updateEntry.Version, updateEntry.Built.String())
		return true, nil
	}
	stage.Current = "no update available"
	return false, nil
}

// IsUpdateAvailable indicates if there is a new update available as a boolean, and returns the latest listing information
// available for this schema.
func (c *Curator) IsUpdateAvailable() (bool, *curation.ListingEntry, error) {
	log.Debugf("checking for available database updates")

	listing, err := c.newListingFromURL(c.fs, c.listingURL)
	if err != nil {
		return false, nil, err
	}

	updateEntry := listing.BestUpdate(c.targetSchema)
	if updateEntry == nil {
		return false, nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	current, err := curation.NewMetadataFromDir(c.fs, c.dbDir)
	if err != nil {
		return false, nil, fmt.Errorf("current metadata corrupt: %w", err)
	}

	if current.IsSupersededBy(updateEntry) {
		log.Debugf("database update available: %s", updateEntry)
		return true, updateEntry, nil
	}
	log.Debugf("no database update available")

	return false, nil, nil
}

// UpdateTo updates the existing DB with the specific other version provided from a listing entry.
func (c *Curator) UpdateTo(listing *curation.ListingEntry, downloadProgress, importProgress *progress.Manual, stage *progress.Stage) error {
	stage.Current = "downloading"
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := c.download(listing, downloadProgress)
	if err != nil {
		return err
	}

	stage.Current = "validating"
	err = c.validate(tempDir)
	if err != nil {
		return err
	}

	stage.Current = "importing"
	err = c.activate(tempDir)
	if err != nil {
		return err
	}
	stage.Current = "updated"
	importProgress.N = importProgress.Total
	importProgress.SetCompleted()

	return c.fs.RemoveAll(tempDir)
}

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *Curator) Validate() error {
	return c.validate(c.dbDir)
}

// ImportFrom takes a DB archive file and imports it into the final DB location.
func (c *Curator) ImportFrom(dbArchivePath string) error {
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := ioutil.TempDir("", "grype-import")
	if err != nil {
		return fmt.Errorf("unable to create db temp dir: %w", err)
	}

	f, err := os.Open(dbArchivePath)
	if err != nil {
		return fmt.Errorf("unable to open archive (%s): %w", dbArchivePath, err)
	}
	defer func() {
		err = f.Close()
		if err != nil {
			log.Errorf("unable to close archive (%s): %w", dbArchivePath, err)
		}
	}()

	err = file.UnTarGz(tempDir, f)
	if err != nil {
		return err
	}

	err = c.validate(tempDir)
	if err != nil {
		return err
	}

	err = c.activate(tempDir)
	if err != nil {
		return err
	}

	return c.fs.RemoveAll(tempDir)
}

func (c *Curator) download(listing *curation.ListingEntry, downloadProgress *progress.Manual) (string, error) {
	tempDir, err := ioutil.TempDir("", "grype-scratch")
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
	err = c.downloader.GetToDir(tempDir, listing.URL.String(), downloadProgress)
	if err != nil {
		return "", fmt.Errorf("unable to download db: %w", err)
	}

	return tempDir, nil
}

func (c *Curator) validate(dbDirPath string) error {
	// check that the disk checksum still matches the db payload
	metadata, err := curation.NewMetadataFromDir(c.fs, dbDirPath)
	if err != nil {
		return fmt.Errorf("failed to parse database metadata (%s): %w", dbDirPath, err)
	}
	if metadata == nil {
		return fmt.Errorf("database metadata not found: %s", dbDirPath)
	}

	if c.validateByHashOnGet {
		dbPath := path.Join(dbDirPath, FileName)
		valid, actualHash, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("bad db checksum (%s): %q vs %q", dbPath, metadata.Checksum, actualHash)
		}
	}

	if c.targetSchema != metadata.Version {
		return fmt.Errorf("unsupported database version: have=%d want=%d", metadata.Version, c.targetSchema)
	}

	// TODO: add version checks here to ensure this version of the application can use this database version (relative to what the DB says, not JUST the metadata!)

	return nil
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

// newListingFromURL loads a Listing from a URL.
func (c Curator) newListingFromURL(fs afero.Fs, listingURL string) (curation.Listing, error) {
	tempFile, err := afero.TempFile(fs, "", "grype-db-listing")
	if err != nil {
		return curation.Listing{}, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer func() {
		err := fs.RemoveAll(tempFile.Name())
		if err != nil {
			log.Errorf("failed to remove file (%s): %w", tempFile.Name(), err)
		}
	}()

	// download the listing file
	err = c.downloader.GetFile(tempFile.Name(), listingURL)
	if err != nil {
		return curation.Listing{}, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := curation.NewListingFromFile(fs, tempFile.Name())
	if err != nil {
		return curation.Listing{}, err
	}
	return listing, nil
}
