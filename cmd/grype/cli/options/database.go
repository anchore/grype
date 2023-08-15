package options

import (
	"path"
	"time"

	"github.com/adrg/xdg"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
)

type Database struct {
	Dir                   string        `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL             string        `yaml:"update-url" json:"update-url" mapstructure:"update-url"`
	CACert                string        `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
	AutoUpdate            bool          `yaml:"auto-update" json:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart bool          `yaml:"validate-by-hash-on-start" json:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
	ValidateAge           bool          `yaml:"validate-age" json:"validate-age" mapstructure:"validate-age"`
	MaxAllowedBuiltAge    time.Duration `yaml:"max-allowed-built-age" json:"max-allowed-built-age" mapstructure:"max-allowed-built-age"`
}

func DatabaseDefault(id clio.Identification) Database {
	return Database{
		Dir:         path.Join(xdg.CacheHome, id.Name, "db"),
		UpdateURL:   internal.DBUpdateURL,
		AutoUpdate:  true,
		ValidateAge: true,
		// After this period (5 days) the db data is considered stale
		MaxAllowedBuiltAge: time.Hour * 24 * 5,
	}
}

func (cfg Database) ToCuratorConfig() db.Config {
	return db.Config{
		DBRootDir:           cfg.Dir,
		ListingURL:          cfg.UpdateURL,
		CACert:              cfg.CACert,
		ValidateByHashOnGet: cfg.ValidateByHashOnStart,
		ValidateAge:         cfg.ValidateAge,
		MaxAllowedBuiltAge:  cfg.MaxAllowedBuiltAge,
	}
}
