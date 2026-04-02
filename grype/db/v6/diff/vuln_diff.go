package diff

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	"github.com/anchore/grype/internal/log"
)

func (d *DBDiffer) diffVulns() (*VulnerabilityDiff, error) {
	startTime := time.Now()

	err := d.createVulnsTables()
	if err != nil {
		return nil, err
	}

	// collect all per-package/CPE diff entries
	diffs := &VulnerabilityDiff{}

	if d.config.IncludeKEV() {
		kevDiffs, err := d.findKevDiffs()
		if err != nil {
			return nil, err
		}

		for id := range kevDiffs {
			diffs.Modified = append(diffs.Modified, VulnerabilityID{
				ID: id,
			})
		}
	}

	if d.config.IncludeEPSS() {
		epssDiffs, err := d.findEpssDiffs()
		if err != nil {
			return nil, err
		}

		for id := range epssDiffs {
			diffs.Modified = append(diffs.Modified, VulnerabilityID{
				ID: id,
			})
		}
	}

	changeTypes := []struct {
		name string
		fn   func(*VulnerabilityDiff) (int, error)
	}{
		{"added vulnerabilities", d.findVulnsAdded},
		{"removed vulnerabilities", d.findVulnsRemoved},
		{"modified vulnerabilities", d.findVulnsModified},
	}

	for _, v := range changeTypes {
		startTime := time.Now()
		count, err := v.fn(diffs)
		if err != nil {
			return nil, fmt.Errorf("%q failed: %w", v.name, err)
		}
		log.Infof("%s found %v records; took %s", v.name, count, time.Since(startTime))
	}

	log.Infof("vulnerability diff completed in %s", time.Since(startTime))

	for _, vulns := range []*[]VulnerabilityID{&diffs.Added, &diffs.Modified, &diffs.Removed} {
		slices.SortFunc(*vulns, func(a, b VulnerabilityID) int {
			if a.Provider != b.Provider {
				return strings.Compare(a.Provider, b.Provider)
			}
			return strings.Compare(a.ID, b.ID)
		})
	}
	return diffs, nil
}

// findVulnsAdded gets added vulnerabilities in the new database
func (d *DBDiffer) findVulnsAdded(diff *VulnerabilityDiff) (int, error) {
	out := map[VulnerabilityID]struct{}{}
	var rows []vulnRow
	err := d.db.Raw(`
		SELECT provider_id, name FROM diff_vuln_added
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		out[VulnerabilityID{r.ProviderID, r.VulnName}] = struct{}{}
	}
	diff.Added = append(diff.Added, maps.Keys(out)...)
	return len(out), nil
}

// findVulnsRemoved gets removed vulnerabilities in the new database
func (d *DBDiffer) findVulnsRemoved(diff *VulnerabilityDiff) (int, error) {
	out := map[VulnerabilityID]struct{}{}
	var rows []vulnRow
	err := d.db.Raw(`
		SELECT provider_id, name FROM diff_vuln_removed
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		out[VulnerabilityID{r.ProviderID, r.VulnName}] = struct{}{}
	}
	diff.Removed = append(diff.Removed, maps.Keys(out)...)
	return len(out), nil
}

// findVulnsModified gets modified packages / vulnerabilities in the new database
func (d *DBDiffer) findVulnsModified(diff *VulnerabilityDiff) (int, error) {
	out := map[VulnerabilityID]struct{}{}
	var rows []vulnRow
	err := d.db.Raw(`
		SELECT provider_id, name FROM diff_vuln_modified
	`).Scan(&rows).Error
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		out[VulnerabilityID{r.ProviderID, r.VulnName}] = struct{}{}
	}
	diff.Modified = append(diff.Modified, maps.Keys(out)...)
	return len(out), nil
}
