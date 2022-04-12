package config

import (
	"path"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
)

type database struct {
	Dir                   string `yaml:"cache-dir" json:"cacheDir" mapstructure:"cache-dir"`
	UpdateURL             string `yaml:"update-url" json:"updateUrl" mapstructure:"update-url"`
	CACert                string `yaml:"ca-cert" json:"caCert" mapstructure:"ca-cert"`
	AutoUpdate            bool   `yaml:"auto-update" json:"autoUpdate" mapstructure:"auto-update"`
	ValidateByHashOnStart bool   `yaml:"validate-by-hash-on-start" json:"validateByHashOnStart" mapstructure:"validate-by-hash-on-start"`
}

func (cfg database) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("db.cache-dir", path.Join(xdg.CacheHome, internal.ApplicationName, "db"))
	v.SetDefault("db.update-url", internal.DBUpdateURL)
	v.SetDefault("db.ca-cert", "")
	v.SetDefault("db.auto-update", true)
	v.SetDefault("db.validate-by-hash-on-start", false)
}

func (cfg database) ToCuratorConfig() db.Config {
	return db.Config{
		DBRootDir:           cfg.Dir,
		ListingURL:          cfg.UpdateURL,
		CACert:              cfg.CACert,
		ValidateByHashOnGet: cfg.ValidateByHashOnStart,
	}
}
