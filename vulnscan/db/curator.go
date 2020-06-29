package db

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/anchore/vulnscan-db/pkg/db"
	"github.com/anchore/vulnscan-db/pkg/db/curation"
	"github.com/anchore/vulnscan-db/pkg/store/sqlite"
	"github.com/anchore/vulnscan/internal/file"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/hashicorp/go-version"
	"github.com/spf13/afero"
)

const (
	supportedVersion = "<1.0.0"
	FileName         = db.StoreFileName
)

type Config struct {
	DbDir      string
	ListingURL string
}

type Curator struct {
	fs                afero.Fs
	config            Config
	client            file.Getter
	versionConstraint version.Constraints
}

func NewCurator(cfg Config) (Curator, error) {
	constraint, err := version.NewConstraint(supportedVersion)
	if err != nil {
		return Curator{}, fmt.Errorf("unable to set DB curator version constraint (%s): %w", supportedVersion, err)
	}

	return Curator{
		config:            cfg,
		fs:                afero.NewOsFs(),
		versionConstraint: constraint,
		client:            &file.HashiGoGetter{},
	}, nil
}

func (c *Curator) GetStore() (db.VulnerabilityStoreReader, error) {
	// ensure the DB is ok
	err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("vulnerability database is corrupt (run db update to correct): %+v", err)
	}

	// provide an abstraction for the underlying store
	connectOptions := sqlite.Options{
		FilePath: path.Join(c.config.DbDir, FileName),
	}
	store, _, err := sqlite.NewStore(&connectOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to get vulnerability store: %w", err)
	}
	return store, nil
}

func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.config.DbDir)
}

func (c *Curator) IsUpdateAvailable() (bool, *curation.ListingEntry, error) {
	log.Debugf("checking for available database updates")

	listing, err := curation.NewListingFromURL(c.fs, c.client, c.config.ListingURL)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get listing file: %w", err)
	}

	updateEntry := listing.BestUpdate(c.versionConstraint)
	if updateEntry == nil {
		return false, nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	current, err := curation.NewMetadataFromDir(c.fs, c.config.DbDir)
	if err != nil {
		return false, nil, fmt.Errorf("current metadata corrupt: %w", err)
	}

	if current.IsSupercededBy(updateEntry) {
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
	tempDir, err := ioutil.TempDir("", "vulnscan-import")
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
	tempDir, err := ioutil.TempDir("", "vulnscan-scratch")
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
	valid, err := file.ValidateByHash(c.fs, dbPath, metadata.Checksum)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("bad db checksum (%s)", dbDirPath)
	}

	if !c.versionConstraint.Check(metadata.Version) {
		return fmt.Errorf("unsupported database version: version=%s constraint=%s", metadata.Version.String(), c.versionConstraint.String())
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
