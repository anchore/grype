package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/anchore/grype-db/pkg/curation"
	"github.com/anchore/grype-db/pkg/db"
	"github.com/anchore/grype-db/pkg/store/sqlite/reader"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/spf13/afero"
)

const (
	FileName = db.VulnerabilityStoreFileName
)

type Config struct {
	DbDir      string
	ListingURL string
}

type Curator struct {
	fs           afero.Fs
	config       Config
	client       file.Getter
	targetSchema int
}

func NewCurator(cfg Config) (Curator, error) {
	return Curator{
		config:       cfg,
		fs:           afero.NewOsFs(),
		targetSchema: db.SchemaVersion,
		client:       &file.HashiGoGetter{},
	}, nil
}

func (c *Curator) GetStore() (db.VulnerabilityStoreReader, error) {
	// ensure the DB is ok
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("vulnerability database is corrupt (run db update to correct): %+v", err)
	}

	dbPath := path.Join(c.config.DbDir, FileName)
	s, _, err := reader.NewStore(dbPath)
	return s, err
}

func (c *Curator) Status() Status {
	metadata, err := curation.NewMetadataFromDir(c.fs, c.config.DbDir)
	if err != nil {
		err = fmt.Errorf("failed to parse database metadata (%s): %w", c.config.DbDir, err)
	}
	if metadata == nil {
		err = fmt.Errorf("database metadata not found at %q", c.config.DbDir)
	}

	if err == nil {
		err = c.Validate()
	}

	return Status{
		Age:                   metadata.Built,
		CurrentSchemaVersion:  metadata.Version,
		RequiredSchemeVersion: db.SchemaVersion,
		Location:              c.config.DbDir,
		Err:                   err,
	}
}

func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.config.DbDir)
}

func (c *Curator) IsUpdateAvailable() (bool, *curation.ListingEntry, error) {
	log.Debugf("checking for available database updates")

	listing, err := curation.NewListingFromURL(c.fs, c.client, c.config.ListingURL)
	if err != nil {
		return false, nil, err
	}

	updateEntry := listing.BestUpdate(c.targetSchema)
	if updateEntry == nil {
		return false, nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	current, err := curation.NewMetadataFromDir(c.fs, c.config.DbDir)
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

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *Curator) Validate() error {
	return c.validate(c.config.DbDir)
}

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

func (c *Curator) UpdateTo(listing *curation.ListingEntry) error {
	// note: the temp directory is persisted upon download/validation/activation failure to allow for investigation
	tempDir, err := c.download(listing)
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

func (c *Curator) download(listing *curation.ListingEntry) (string, error) {
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
	err = c.client.GetToDir(tempDir, listing.URL.String())
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

	dbPath := path.Join(dbDirPath, FileName)
	valid, actualHash, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("bad db checksum (%s): %q vs %q", dbPath, metadata.Checksum, actualHash)
	}

	if c.targetSchema != metadata.Version {
		return fmt.Errorf("unsupported database version: have=%d want=%d", metadata.Version, c.targetSchema)
	}

	// TODO: add version checks here to ensure this version of the application can use this database version (relative to what the DB says, not JUST the metadata!)

	return nil
}

// activate swaps over the downloaded db to the application directory
func (c *Curator) activate(aDbDirPath string) error {
	_, err := c.fs.Stat(c.config.DbDir)
	if !os.IsNotExist(err) {
		// remove any previous databases
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing database: %w", err)
		}
	}

	// ensure there is an application db directory
	err = c.fs.MkdirAll(c.config.DbDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	// activate the new db cache
	return file.CopyDir(c.fs, aDbDirPath, c.config.DbDir)
}
