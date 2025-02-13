package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

const (
	jsonOutputFormat  = "json"
	tableOutputFormat = "table"
	textOutputFormat  = "text"
)

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
