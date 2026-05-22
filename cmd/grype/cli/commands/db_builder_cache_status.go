package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/gookit/color"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/entry"
)

// DBBuilderCacheStatus walks the on-disk provider workspaces and reports
// each provider's validity, result count, and timestamp. Used as a sanity
// check between 'cache restore' and 'cache backup' in the sync pipeline.
func DBBuilderCacheStatus(app clio.Application) *cobra.Command {
	opts := options.DefaultDatabaseBuild()

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report status of the on-disk provider workspace cache",
		Long: `Inspect each provider workspace under --root and print whether its
state is valid, how many result rows it contains, and when it was last
updated. Exits non-zero if any selected provider is invalid (or has fewer
rows than --min-rows when set).`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return disableUI(app)(cmd, args)
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderCacheStatus(opts)
		},
	}

	return app.SetupCommand(cmd, &dbBuilderConfigWrapper{DBBuilder: opts})
}

func runDBBuilderCacheStatus(opts *options.DatabaseBuild) error {
	providerNames, err := readProviderNamesFromRoot(opts.Provider.Root)
	if err != nil {
		return err
	}

	providerNames, missingProvidersErr := validateRequestedProviders(providerNames, opts.Provider.IncludeFilter)

	var sds []*dbprovider.State
	var errs []error

	for _, name := range providerNames {
		workspace := dbprovider.NewWorkspace(opts.Provider.Root, name)
		sd, err := workspace.ReadState()
		if err != nil {
			sds = append(sds, nil)
			errs = append(errs, err)
			continue
		}

		if err := sd.Verify(workspace.Path()); err != nil {
			sds = append(sds, nil)
			errs = append(errs, err)
			continue
		}

		errs = append(errs, nil)
		sds = append(sds, sd)
	}

	success := true

	for idx, sd := range sds {
		validMsg := "valid"
		isValid := true
		if errs[idx] != nil {
			validMsg = fmt.Sprintf("INVALID (%s)", errs[idx].Error())
			isValid = false
		} else if sd == nil {
			validMsg = "INVALID (no state description found)"
			isValid = false
		}

		var count int64
		name := providerNames[idx]

		if sd != nil {
			name = sd.Provider
			counter := func() (int64, error) {
				return entry.Count(sd.Store, sd.ResultPaths())
			}
			count, err = validateMinRowsCount(opts.Cache.MinRows, counter)
			if err != nil {
				isValid = false
				validMsg = fmt.Sprintf("INVALID (%s)", err.Error())
			}
		}

		success = success && isValid

		fmt.Printf("  • %s\n", name)
		statusFmt := color.HiRed
		if isValid {
			fmt.Printf("    ├── results: %d\n", count)
			fmt.Printf("    ├── created: %s\n", sd.Timestamp.Format(time.RFC3339))
			statusFmt = color.HiGreen
		}

		fmt.Printf("    └── status:  %s\n", statusFmt.Sprint(validMsg))
	}

	if missingProvidersErr != nil {
		success = false
		fmt.Printf("INVALID (%s)\n", missingProvidersErr.Error())
	}

	if !success {
		os.Exit(1)
	}
	return nil
}

func validateMinRowsCount(minRows int, counter func() (int64, error)) (int64, error) {
	count, err := counter()
	if err != nil {
		return 0, fmt.Errorf("unable to count entries: %w", err)
	}
	if count <= int64(minRows) {
		return 0, fmt.Errorf("data has %d rows, must have more than %d", count, minRows)
	}
	return count, nil
}
