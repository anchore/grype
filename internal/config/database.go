package config

import (
	"path"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal"
	"github.com/spf13/viper"
)

type database struct {
	Dir                   string `mapstructure:"cache-dir"`
	UpdateURL             string `mapstructure:"update-url"`
	AutoUpdate            bool   `mapstructure:"auto-update"`
	ValidateByHashOnStart bool   `mapstructure:"validate-by-hash-on-start"`
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
