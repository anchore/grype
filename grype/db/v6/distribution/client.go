package distribution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-progress"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"
)

const DatabaseFileName = "vulnerability.db"

type Config struct {
	// fetch parameters
	ListingURL string
	CACert     string

	// post-fetch validations
	ValidateByHashOnGet bool

	// timeouts
	ListingFileTimeout time.Duration
	UpdateTimeout      time.Duration
}

type Client struct {
	fs                afero.Fs
	listingDownloader file.Getter
	updateDownloader  file.Getter
	config            Config
}

func NewClient(fs afero.Fs, cfg Config) (Client, error) {
	listingClient, err := defaultHTTPClient(fs, cfg.CACert)
	if err != nil {
		return Client{}, err
	}
	listingClient.Timeout = cfg.ListingFileTimeout

	dbClient, err := defaultHTTPClient(fs, cfg.CACert)
	if err != nil {
		return Client{}, err
	}
	dbClient.Timeout = cfg.UpdateTimeout

	return Client{
		fs:                fs,
		listingDownloader: file.NewGetter(listingClient),
		updateDownloader:  file.NewGetter(dbClient),
		config:            cfg,
	}, nil
}

// IsUpdateAvailable indicates if there is a new update available as a boolean, and returns the latest listing information
// available for this schema.
func (c *Client) IsUpdateAvailable(current *DatabaseDescription) (*Archive, error) {
	log.Debugf("checking for available database updates")

	listing, err := c.ListingFromURL()
	if err != nil {
		return nil, err
	}

	updateEntry := listing.Latest
	if updateEntry == nil {
		return nil, fmt.Errorf("no db candidates with correct version available (maybe there is an application update available?)")
	}
	log.Debugf("found database update candidate: %s", updateEntry)

	// compare created data to current db date
	if current.IsSupersededBy(updateEntry.Description) {
		log.Debugf("database update available: %s", updateEntry)
		return updateEntry, nil
	}

	log.Debugf("no database update available")
	return nil, nil
}

func (c *Client) Download(archive *Archive, downloadProgress *progress.Manual) (string, error) {
	defer downloadProgress.SetCompleted()

	// note: as much as I'd like to use the afero FS abstraction here, the go-getter library does not support it
	tempDir, err := os.MkdirTemp("", "grype-db-download")
	if err != nil {
		return "", fmt.Errorf("unable to create db temp dir: %w", err)
	}

	// download the db to the temp dir
	urlStr := path.Join(path.Dir(c.config.ListingURL), archive.Path)
	u, err := url.Parse(urlStr)
	if err != nil {
		removeAllOrLog(afero.NewOsFs(), tempDir)
		return "", fmt.Errorf("unable to parse db URL %q: %w", urlStr, err)
	}

	// from go-getter, adding a checksum as a query string will validate the payload after download
	// note: the checksum query parameter is not sent to the server
	query := u.Query()
	query.Add("checksum", archive.Checksum)
	u.RawQuery = query.Encode()

	// go-getter will automatically extract all files within the archive to the temp dir
	err = c.updateDownloader.GetToDir(tempDir, u.String(), downloadProgress)
	if err != nil {
		removeAllOrLog(afero.NewOsFs(), tempDir)
		return "", fmt.Errorf("unable to download db: %w", err)
	}

	return tempDir, nil
}

// ListingFromURL loads a Listing from a URL.
func (c Client) ListingFromURL() (*ListingDocument, error) {
	tempFile, err := afero.TempFile(c.fs, "", "grype-db-listing")
	if err != nil {
		return nil, fmt.Errorf("unable to create listing temp file: %w", err)
	}
	defer removeAllOrLog(c.fs, tempFile.Name())

	// download the listing file
	err = c.listingDownloader.GetFile(tempFile.Name(), c.config.ListingURL)
	if err != nil {
		return nil, fmt.Errorf("unable to download listing: %w", err)
	}

	// parse the listing file
	listing, err := NewListingFromFile(c.fs, tempFile.Name())
	if err != nil {
		return nil, err
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

func removeAllOrLog(fs afero.Fs, dir string) {
	if err := fs.RemoveAll(dir); err != nil {
		log.WithFields("error", err).Warnf("failed to remove path %q", dir)
	}
}
