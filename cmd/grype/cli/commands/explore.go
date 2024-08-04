package commands

import (
	"github.com/anchore/clio"
	"github.com/spf13/cobra"
)

func Explore(app clio.Application) *cobra.Command {
	explore := &cobra.Command{
		Use:   "explore",
		Short: "vulnerability explore operations",
	}

	explore.AddCommand(
		ExploreCVE(app),
	)

	return explore
}
