package kev

import (
	"regexp"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	internal2 "github.com/anchore/grype/grype/db/v6/build/internal/transformers/internal"
)

func Transform(kev unmarshal.KnownExploitedVulnerability, state provider.State) ([]data.Entry, error) {
	return transformers.NewEntries(*internal2.ProviderModel(state), getKev(kev)), nil
}

func getKev(kev unmarshal.KnownExploitedVulnerability) grypeDB.KnownExploitedVulnerabilityHandle {
	urls, notes := getURLs([]string{kev.ShortDescription, kev.RequiredAction}, kev.Notes)
	return grypeDB.KnownExploitedVulnerabilityHandle{
		Cve: kev.CveID,
		BlobValue: &grypeDB.KnownExploitedVulnerabilityBlob{
			Cve:                        kev.CveID,
			VendorProject:              kev.VendorProject,
			Product:                    kev.Product,
			DateAdded:                  internal2.ParseTime(kev.DateAdded),
			RequiredAction:             kev.RequiredAction,
			DueDate:                    internal2.ParseTime(kev.DueDate),
			KnownRansomwareCampaignUse: strings.ToLower(kev.KnownRansomwareCampaignUse),
			Notes:                      notes,
			CWEs:                       kev.CWEs,
			URLs:                       urls,
		},
	}
}

var bracketURLPattern = regexp.MustCompile(`\[(https?://[^\]]+)\]`)

func getURLs(aux []string, notes string) ([]string, string) {
	// let's keep the URLs we find in order but also deduplicate them since we're combining URLs from multiple sources
	urlSet := strset.New()
	var urls []string

	// add URLs from notes first...
	if notes != "" {
		parts := strings.Split(notes, ";")
		cleanedParts := make([]string, 0, len(parts))

		for _, part := range parts {
			part = strings.TrimSpace(part)

			if strings.HasPrefix(strings.ToLower(part), "http") {
				url := part
				if !urlSet.Has(url) {
					urlSet.Add(url)
					urls = append(urls, url)
				}
			} else if part != "" {
				cleanedParts = append(cleanedParts, part)
			}
		}

		notes = strings.Join(cleanedParts, "; ")
	}

	// ...then add URLs from the other fields
	for _, text := range aux {
		matches := bracketURLPattern.FindAllStringSubmatch(text, -1)
		for _, match := range matches {
			if len(match) > 1 {
				url := match[1]
				if !urlSet.Has(url) {
					urlSet.Add(url)
					urls = append(urls, url)
				}
			}
		}
	}

	return urls, notes
}
