package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
)

const (
	jsonOutputFormat  = "json"
	tableOutputFormat = "table"
	textOutputFormat  = "text"
)

type DBOptions struct {
	DB           options.Database     `yaml:"db" json:"db" mapstructure:"db"`
	Experimental options.Experimental `yaml:"exp" json:"exp" mapstructure:"exp"`
}

func dbOptionsDefault(id clio.Identification) *DBOptions {
	dbDefaults := options.DefaultDatabase(id)
	// by default, require update check success for db operations which check for updates
	dbDefaults.RequireUpdateCheck = true
	return &DBOptions{
		DB: dbDefaults,
	}
}

func DB(app clio.Application) *cobra.Command {
	db := &cobra.Command{
		Use:   "db",
		Short: "vulnerability database operations",
	}

	db.AddCommand(
		DBCheck(app),
		DBDelete(app),
		DBDiff(app),
		DBImport(app),
		DBList(app),
		DBStatus(app),
		DBUpdate(app),
		DBSearch(app),
		DBProviders(app),
	)

	return db
}
