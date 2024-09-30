package distribution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/log"
)

type Config struct {
	ID clio.Identification

	// check/fetch parameters
	LatestURL string
	CACert    string

	// validations
	ValidateByHashOnGet bool
	RequireUpdateCheck  bool

	// timeouts
	CheckTimeout  time.Duration
	UpdateTimeout time.Duration
}

type Client interface {
	IsUpdateAvailable(current *v6.Description) (*Archive, error)
	Download(archive Archive, dest string, downloadProgress *progress.Manual) (string, error)
}

type client struct {
	fs               afero.Fs
	latestHTTPClient *http.Client
	updateDownloader file.Getter
	config           Config
}

func DefaultConfig() Config {
	return Config{
		LatestURL:           "https://grype.anchore.io/databases/latest.json",
		ValidateByHashOnGet: true,
		RequireUpdateCheck:  false,
		CheckTimeout:        30 * time.Second,
		UpdateTimeout:       300 * time.Second,
	}
}

func NewClient(cfg Config) (Client, error) {
	fs := afero.NewOsFs()
	latestClient, err := defaultHTTPClient(fs, cfg.CACert, withClientTimeout(cfg.CheckTimeout))
	if err != nil {
		return client{}, err
	}

	dbClient, err := defaultHTTPClient(fs, cfg.CACert, withClientTimeout(cfg.UpdateTimeout))
	if err != nil {
		return client{}, err
	}

	return client{
		fs:               fs,
		latestHTTPClient: latestClient,
		updateDownloader: file.NewGetter(cfg.ID, dbClient),
		config:           cfg,
	}, nil
}

// IsUpdateAvailable indicates if there is a new update available as a boolean, and returns the latest db information
// available for this schema.
func (c client) IsUpdateAvailable(current *v6.Description) (*Archive, error) {
	log.Debugf("checking for available database updates")

	updateEntry, err := c.latestFromURL()
	if err != nil {
		if c.config.RequireUpdateCheck {
			return nil, fmt.Errorf("check for vulnerability database update failed: %+v", err)
		}
		log.Warnf("unable to check for vulnerability database update")
		log.Debugf("check for vulnerability update failed: %+v", err)
	}
	return c.isUpdateAvailable(current, updateEntry)
}

func (c client) isUpdateAvailable(current *v6.Description, candidate *LatestDocument) (*Archive, error) {
	if candidate == nil {
		return nil, nil
	}

	// compare created data to current db date
	if isSupersededBy(current, candidate.Archive.Description) {
		log.Debugf("database update available: %s", candidate.Archive.Description)
		return &candidate.Archive, nil
	}

	log.Debugf("no database update available")
	return nil, nil
}

func (c client) Download(archive Archive, dest string, downloadProgress *progress.Manual) (string, error) {
	defer downloadProgress.SetCompleted()

	// note: as much as I'd like to use the afero FS abstraction here, the go-getter library does not support it
	tempDir, err := os.MkdirTemp(dest, "grype-db-download")
	if err != nil {
		return "", fmt.Errorf("unable to create db temp dir: %w", err)
	}

	// download the db to the temp dir
	u, err := url.Parse(c.config.LatestURL)
	if err != nil {
		removeAllOrLog(afero.NewOsFs(), tempDir)
		return "", fmt.Errorf("unable to parse db URL %q: %w", c.config.LatestURL, err)
	}

	u.Path = path.Join(path.Dir(u.Path), path.Clean(archive.Path))

	// from go-getter, adding a checksum as a query string will validate the payload after download
	// note: the checksum query parameter is not sent to the server
	query := u.Query()
	if archive.Checksum != "" {
		query.Add("checksum", archive.Checksum)
	}
	u.RawQuery = query.Encode()

	// go-getter will automatically extract all files within the archive to the temp dir
	err = c.updateDownloader.GetToDir(tempDir, u.String(), downloadProgress)
	if err != nil {
		removeAllOrLog(afero.NewOsFs(), tempDir)
		return "", fmt.Errorf("unable to download db: %w", err)
	}

	return tempDir, nil
}

// latestFromURL loads a LatestDocument from a URL.
func (c client) latestFromURL() (*LatestDocument, error) {
	resp, err := c.latestHTTPClient.Get(c.config.LatestURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch latest.json: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch latest.json: %s", resp.Status)
	}

	defer resp.Body.Close()

	return NewLatestFromReader(resp.Body)
}

func withClientTimeout(timeout time.Duration) func(*http.Client) {
	return func(c *http.Client) {
		c.Timeout = timeout
	}
}

func defaultHTTPClient(fs afero.Fs, caCertPath string, postProcessor ...func(*http.Client)) (*http.Client, error) {
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

	for _, pp := range postProcessor {
		pp(httpClient)
	}

	return httpClient, nil
}

func removeAllOrLog(fs afero.Fs, dir string) {
	if err := fs.RemoveAll(dir); err != nil {
		log.WithFields("error", err).Warnf("failed to remove path %q", dir)
	}
}

func isSupersededBy(m *v6.Description, other v6.Description) bool {
	if m == nil {
		log.Debug("cannot find existing metadata, using update...")
		// any valid update beats no database, use it!
		return true
	}

	otherModelPart, otherOk := other.SchemaVersion.ModelPart()
	currentModelPart, currentOk := m.SchemaVersion.ModelPart()

	if !otherOk {
		log.Error("existing database has no schema version, doing nothing...")
		return false
	}

	if !currentOk {
		log.Error("update has no schema version, doing nothing...")
		return false
	}

	if otherModelPart != currentModelPart {
		log.WithFields("want", currentModelPart, "received", otherModelPart).Warn("update is for a different DB schema, skipping...")
		return false
	}

	if other.Built.After(m.Built.Time) {
		log.WithFields("existing", m.Built.String(), "candidate", other.Built.String()).Debug("existing database is older than candidate update, using update...")
		// the listing is newer than the existing db, use it!
		return true
	}

	log.Debugf("existing database is already up to date")
	return false
}
