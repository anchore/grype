package config

import (
	"path"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
	"github.com/spf13/viper"
)

type database struct {
	Dir                   string `yaml:"cache-dir" json:"cache-dir" mapstructure:"cache-dir"`
	UpdateURL             string `yaml:"update-url" json:"update-url" mapstructure:"update-url"`
	AutoUpdate            bool   `yaml:"auto-update" json:"auto-update" mapstructure:"auto-update"`
	ValidateByHashOnStart bool   `yaml:"validate-by-hash-on-start" json:"validate-by-hash-on-start" mapstructure:"validate-by-hash-on-start"`
}

func (cfg database) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("db.cache-dir", path.Join(xdg.CacheHome, internal.ApplicationName, "db"))
	v.SetDefault("db.update-url", internal.DBUpdateURL)
	v.SetDefault("db.auto-update", true)
	v.SetDefault("db.validate-by-hash-on-start", false)
}

func (cfg database) ToCuratorConfig() db.Config {
	return db.Config{
		DbRootDir:           cfg.Dir,
		ListingURL:          cfg.UpdateURL,
		ValidateByHashOnGet: cfg.ValidateByHashOnStart,
	}
}
