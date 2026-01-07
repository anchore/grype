package epss

import (
	"fmt"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	internal2 "github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
)

func Transform(entry unmarshal.EPSS, state provider.State) ([]data.Entry, error) {
	date := internal2.ParseTime(entry.Date)
	if date == nil {
		return nil, fmt.Errorf("failed to parse date: %q", entry.Date)
	}
	return transformers.NewEntries(*internal2.ProviderModel(state), getEPSS(entry, *date)), nil
}

func getEPSS(entry unmarshal.EPSS, date time.Time) grypeDB.EpssHandle {
	return grypeDB.EpssHandle{
		Cve:        entry.CVE,
		Epss:       entry.EPSS,
		Percentile: entry.Percentile,
		Date:       date,
	}
}
