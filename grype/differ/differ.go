package differ

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"

	"github.com/olekukonko/tablewriter"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/db"
	v5 "github.com/anchore/grype/grype/db/v5"
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

func (d *Differ) SetBaseDB(base string) error {
	return d.setOrDownload(&d.baseCurator, base)
}

func (d *Differ) SetTargetDB(target string) error {
	return d.setOrDownload(&d.targetCurator, target)
}

func (d *Differ) setOrDownload(curator *db.Curator, filenameOrURL string) error {
	u, err := url.ParseRequestURI(filenameOrURL)

	if err != nil || u.Scheme == "" {
		*curator, err = db.NewCurator(db.Config{
			DBRootDir: filenameOrURL,
		})
		if err != nil {
			return err
		}
	} else {
		listings, err := d.baseCurator.ListingFromURL()
		if err != nil {
			return err
		}

		available := listings.Available
		dbs := available[v5.SchemaVersion]

		var listing *db.ListingEntry

		for _, d := range dbs {
			database := d
			if *d.URL == *u {
				listing = &database
			}
		}

		if listing == nil {
			return fmt.Errorf("unable to find listing for url: %s", filenameOrURL)
		}

		if err := download(curator, listing); err != nil {
			return fmt.Errorf("unable to download vulnerability database: %+v", err)
		}
	}

	return nil
}

func download(curator *db.Curator, listing *db.ListingEntry) error {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := progress.NewManual(1)
	stage := &progress.Stage{
		Current: "checking available databases",
	}
	downloadProgress := progress.NewManual(1)
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

func (d *Differ) DiffDatabases() (*[]v5.Diff, error) {
	baseStore, baseDBCloser, err := d.baseCurator.GetStore()
	if err != nil {
		return nil, err
	}

	defer baseDBCloser.Close()

	targetStore, targetDBCloser, err := d.targetCurator.GetStore()
	if err != nil {
		return nil, err
	}

	defer targetDBCloser.Close()

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

func (d *Differ) Present(outputFormat string, diff *[]v5.Diff, output io.Writer) error {
	if diff == nil {
		return nil
	}

	switch outputFormat {
	case "table":
		rows := [][]string{}
		for _, d := range *diff {
			rows = append(rows, []string{d.ID, d.Namespace, d.Reason})
		}

		table := tablewriter.NewWriter(output)
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
		enc := json.NewEncoder(output)
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
