package config

import (
	"path"
	"time"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
)

type database struct {
	Dir                   string        `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL             string        `yaml:"update-url" json:"update-url" mapstructure:"update-url"`
	CACert                string        `yaml:"ca-cert" json:"ca-cert" mapstructure:"ca-cert"`
	AutoUpdate            bool          `yaml:"auto-update" json:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart bool          `yaml:"validate-by-hash-on-start" json:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
	ValidateAge           bool          `yaml:"validate-age" json:"validate-age" mapstructure:"validate-age"`
	MaxAllowedBuiltAge    time.Duration `yaml:"max-allowed-built-age" json:"max-allowed-built-age" mapstructure:"max-allowed-built-age"`
}

func (cfg database) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("db.cache-dir", path.Join(xdg.CacheHome, internal.ApplicationName, "db"))
	v.SetDefault("db.update-url", internal.DBUpdateURL)
	v.SetDefault("db.ca-cert", "")
	v.SetDefault("db.auto-update", true)
	v.SetDefault("db.validate-by-hash-on-start", false)
	v.SetDefault("db.validate-age", true)
	// After this period (5 days) the db data is considered stale
	v.SetDefault("db.max-allowed-built-age", time.Hour*24*5)
}

func (cfg database) ToCuratorConfig() db.Config {
	return db.Config{
		DBRootDir:           cfg.Dir,
		ListingURL:          cfg.UpdateURL,
		CACert:              cfg.CACert,
		ValidateByHashOnGet: cfg.ValidateByHashOnStart,
		ValidateAge:         cfg.ValidateAge,
		MaxAllowedBuiltAge:  cfg.MaxAllowedBuiltAge,
	}
}
