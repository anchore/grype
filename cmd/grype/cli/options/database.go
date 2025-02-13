package options

import (
	"path"
	"time"

	"github.com/adrg/xdg"

	"github.com/anchore/clio"
	"github.com/anchore/grype/internal"
)

type Database struct {
	ID                      clio.Identification `yaml:"-" json:"-" mapstructure:"-"`
	Dir                     string              `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL               string              `yaml:"update-url" json:"update-url" mapstructure:"update-url"`
	CACert                  string              `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
	AutoUpdate              bool                `yaml:"auto-update" json:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart   bool                `yaml:"validate-by-hash-on-start" json:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
	ValidateAge             bool                `yaml:"validate-age" json:"validate-age" mapstructure:"validate-age"`
	MaxAllowedBuiltAge      time.Duration       `yaml:"max-allowed-built-age" json:"max-allowed-built-age" mapstructure:"max-allowed-built-age"`
	RequireUpdateCheck      bool                `yaml:"require-update-check" json:"require-update-check" mapstructure:"require-update-check"`
	UpdateAvailableTimeout  time.Duration       `yaml:"update-available-timeout" json:"update-available-timeout" mapstructure:"update-available-timeout"`
	UpdateDownloadTimeout   time.Duration       `yaml:"update-download-timeout" json:"update-download-timeout" mapstructure:"update-download-timeout"`
	MaxUpdateCheckFrequency time.Duration       `yaml:"max-update-check-frequency" json:"max-update-check-frequency" mapstructure:"max-update-check-frequency"`
}

var _ interface {
	clio.FieldDescriber
} = (*Database)(nil)

const (
	defaultMaxDBAge                time.Duration = time.Hour * 24 * 5
	defaultUpdateAvailableTimeout                = time.Second * 30
	defaultUpdateDownloadTimeout                 = time.Second * 300
	defaultMaxUpdateCheckFrequency               = time.Hour * 2
)

func DefaultDatabase(id clio.Identification) Database {
	return Database{
		ID:          id,
		Dir:         path.Join(xdg.CacheHome, id.Name, "db"),
		UpdateURL:   internal.DBUpdateURL,
		AutoUpdate:  true,
		ValidateAge: true,
		// After this period (5 days) the db data is considered stale
		MaxAllowedBuiltAge:      defaultMaxDBAge,
		RequireUpdateCheck:      false,
		UpdateAvailableTimeout:  defaultUpdateAvailableTimeout,
		UpdateDownloadTimeout:   defaultUpdateDownloadTimeout,
		MaxUpdateCheckFrequency: defaultMaxUpdateCheckFrequency,
	}
}

func (cfg *Database) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&cfg.Dir, `location to write the vulnerability database cache`)
	descriptions.Add(&cfg.UpdateURL, `URL of the vulnerability database`)
	descriptions.Add(&cfg.CACert, `certificate to trust download the database and listing file`)
	descriptions.Add(&cfg.AutoUpdate, `check for database updates on execution`)
	descriptions.Add(&cfg.ValidateAge, `ensure db build is no older than the max-allowed-built-age`)
	descriptions.Add(&cfg.ValidateByHashOnStart, `validate the database matches the known hash each execution`)
	descriptions.Add(&cfg.MaxAllowedBuiltAge, `Max allowed age for vulnerability database,
age being the time since it was built
Default max age is 120h (or five days)`)
	descriptions.Add(&cfg.RequireUpdateCheck, `fail the scan if unable to check for database updates`)
	descriptions.Add(&cfg.UpdateAvailableTimeout, `Timeout for downloading GRYPE_DB_UPDATE_URL to see if the database needs to be downloaded
This file is ~156KiB as of 2024-04-17 so the download should be quick; adjust as needed`)
	descriptions.Add(&cfg.UpdateDownloadTimeout, `Timeout for downloading actual vulnerability DB
The DB is ~156MB as of 2024-04-17 so slower connections may exceed the default timeout; adjust as needed`)
	descriptions.Add(&cfg.MaxUpdateCheckFrequency, `Maximum frequency to check for vulnerability database updates`)
}
