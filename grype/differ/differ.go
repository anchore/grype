package differ

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"

	"github.com/olekukonko/tablewriter"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/db"
	v4 "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
)

type Differ struct {
	baseCurator   db.Curator
	targetCurator db.Curator
}

func NewDiffer(config db.Config) (*Differ, error) {
	baseCurator, err := db.NewCurator(db.Config{
		DBRootDir:           path.Join(config.DBRootDir, "diff", "base"),
		ListingURL:          config.ListingURL,
		CACert:              config.CACert,
		ValidateByHashOnGet: config.ValidateByHashOnGet,
	})
	if err != nil {
		return nil, err
	}

	targetCurator, err := db.NewCurator(db.Config{
		DBRootDir:           path.Join(config.DBRootDir, "diff", "target"),
		ListingURL:          config.ListingURL,
		CACert:              config.CACert,
		ValidateByHashOnGet: config.ValidateByHashOnGet,
	})
	if err != nil {
		return nil, err
	}

	return &Differ{
		baseCurator:   baseCurator,
		targetCurator: targetCurator,
	}, nil
}

func (d *Differ) DownloadDatabases(baseURL, targetURL *url.URL) error {
	listing, err := d.baseCurator.ListingFromURL()
	if err != nil {
		return err
	}

	listings := listing.Available
	dbs := listings[v4.SchemaVersion]

	var baseListing *db.ListingEntry
	var targetListing *db.ListingEntry

	for _, db := range dbs {
		database := db
		if *db.URL == *baseURL {
			baseListing = &database
		}
		if *db.URL == *targetURL {
			targetListing = &database
		}
	}

	if baseListing == nil {
		return fmt.Errorf("unable to find listing for base url: %s", baseURL.String())
	} else if targetListing == nil {
		return fmt.Errorf("unable to find listing for target url: %s", targetURL.String())
	}

	if err := download(&d.baseCurator, baseListing); err != nil {
		return fmt.Errorf("unable to update base vulnerability database: %+v", err)
	}
	if err := download(&d.targetCurator, targetListing); err != nil {
		return fmt.Errorf("unable to update target vulnerability database: %+v", err)
	}
	return nil
}

func download(curator *db.Curator, listing *db.ListingEntry) error {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := &progress.Manual{
		Total: 1,
	}
	stage := &progress.Stage{
		Current: "checking available databases",
	}
	downloadProgress := &progress.Manual{
		Total: 1,
	}
	aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, importProgress)

	bus.Publish(partybus.Event{
		Type: event.UpdateVulnerabilityDatabase,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: progress.Progressable(aggregateProgress),
		}),
	})

	defer downloadProgress.SetCompleted()
	defer importProgress.SetCompleted()

	return curator.UpdateTo(listing, downloadProgress, importProgress, stage)
}

func (d *Differ) DiffDatabases() (*[]v4.Diff, error) {
	baseStore, err := d.baseCurator.GetStore()
	if err != nil {
		return nil, err
	}

	targetStore, err := d.targetCurator.GetStore()
	if err != nil {
		return nil, err
	}

	return baseStore.DiffStore(targetStore)
}

func (d *Differ) DeleteDatabases() error {
	if err := d.baseCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}
	if err := d.targetCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete vulnerability database: %+v", err)
	}
	return nil
}

func (d *Differ) Present(outputFormat string, diff *[]v4.Diff, output io.Writer) error {
	if diff == nil {
		return nil
	}

	switch outputFormat {
	case "table":
		rows := [][]string{}
		for _, d := range *diff {
			rows = append(rows, []string{d.ID, d.Namespace, d.Reason})
		}

		table := tablewriter.NewWriter(os.Stdout)
		columns := []string{"ID", "Namespace", "Reason"}

		table.SetHeader(columns)
		table.SetAutoWrapText(false)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetAlignment(tablewriter.ALIGN_LEFT)

		table.SetHeaderLine(false)
		table.SetBorder(false)
		table.SetAutoFormatHeaders(true)
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		table.SetTablePadding("  ")
		table.SetNoWhiteSpace(true)

		table.AppendBulk(rows)
		table.Render()
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if err := enc.Encode(*diff); err != nil {
			return fmt.Errorf("failed to encode diff information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}
