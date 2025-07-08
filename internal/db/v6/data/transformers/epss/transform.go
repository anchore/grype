package epss

import (
	"fmt"
	"time"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/db/data/unmarshal"
	v6 "github.com/anchore/grype/internal/db/v6"
	"github.com/anchore/grype/internal/db/v6/data/transformers"
	"github.com/anchore/grype/internal/db/v6/data/transformers/internal"
)

func Transform(entry unmarshal.EPSS, state provider.State) ([]data.Entry, error) {
	date := internal.ParseTime(entry.Date)
	if date == nil {
		return nil, fmt.Errorf("failed to parse date: %q", entry.Date)
	}
	return transformers.NewEntries(*internal.ProviderModel(state), getEPSS(entry, *date)), nil
}

func getEPSS(entry unmarshal.EPSS, date time.Time) v6.EpssHandle {
	return v6.EpssHandle{
		Cve:        entry.CVE,
		Epss:       entry.EPSS,
		Percentile: entry.Percentile,
		Date:       date,
	}
}
