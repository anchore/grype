package options

import (
	"github.com/anchore/clio"
	legacyDistribution "github.com/anchore/grype/grype/db/v5/distribution"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

type DatabaseCommand struct {
	DB           Database     `yaml:"db" json:"db" mapstructure:"db"`
	Experimental Experimental `yaml:"exp" json:"exp" mapstructure:"exp"`
	Developer    developer    `yaml:"dev" json:"dev" mapstructure:"dev"`
}

func DefaultDatabaseCommand(id clio.Identification) *DatabaseCommand {
	dbDefaults := DefaultDatabase(id)
	// by default, require update check success for db operations which check for updates
	dbDefaults.RequireUpdateCheck = true
	return &DatabaseCommand{
		DB: dbDefaults,
	}
}

func (cfg DatabaseCommand) ToCuratorConfig() installation.Config {
	return installation.Config{
		DBRootDir:               cfg.DB.Dir,
		ValidateAge:             cfg.DB.ValidateAge,
		ValidateChecksum:        cfg.DB.ValidateByHashOnStart,
		MaxAllowedBuiltAge:      cfg.DB.MaxAllowedBuiltAge,
		UpdateCheckMaxFrequency: cfg.DB.MaxUpdateCheckFrequency,
		Debug:                   cfg.Developer.DB.Debug,
	}
}

func (cfg DatabaseCommand) ToClientConfig() distribution.Config {
	return distribution.Config{
		ID:                 cfg.DB.ID,
		LatestURL:          cfg.DB.UpdateURL,
		CACert:             cfg.DB.CACert,
		RequireUpdateCheck: cfg.DB.RequireUpdateCheck,
		CheckTimeout:       cfg.DB.UpdateAvailableTimeout,
		UpdateTimeout:      cfg.DB.UpdateDownloadTimeout,
	}
}

func (cfg DatabaseCommand) ToLegacyCuratorConfig() legacyDistribution.Config {
	return legacyDistribution.Config{
		ID:                      cfg.DB.ID,
		DBRootDir:               cfg.DB.Dir,
		ListingURL:              cfg.DB.UpdateURL,
		CACert:                  cfg.DB.CACert,
		ValidateByHashOnGet:     cfg.DB.ValidateByHashOnStart,
		ValidateAge:             cfg.DB.ValidateAge,
		MaxAllowedBuiltAge:      cfg.DB.MaxAllowedBuiltAge,
		RequireUpdateCheck:      cfg.DB.RequireUpdateCheck,
		ListingFileTimeout:      cfg.DB.UpdateAvailableTimeout,
		UpdateTimeout:           cfg.DB.UpdateDownloadTimeout,
		UpdateCheckMaxFrequency: cfg.DB.MaxUpdateCheckFrequency,
	}
}
