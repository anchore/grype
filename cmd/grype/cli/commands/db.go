package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
)

type DBOptions struct {
	DB options.Database `yaml:"db" json:"db" mapstructure:"db"`
}

func dbOptionsDefault(id clio.Identification) *DBOptions {
	return &DBOptions{
		DB: options.DefaultDatabase(id),
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
		DBGetCVE(app),
	)

	return db
}
