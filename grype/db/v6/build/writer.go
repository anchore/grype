package v6

import (
	"fmt"
	"strings"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/internal/transformers"
	"github.com/anchore/grype/internal/log"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath               string
	failOnMissingFixDate bool
	store                grypeDB.ReadWriter
	providerCache        map[string]grypeDB.Provider
	states               provider.States
	severityCache        map[string]grypeDB.Severity
}

func NewWriter(directory string, states provider.States, failOnMissingFixDate bool) (data.Writer, error) {
	cfg := grypeDB.Config{
		DBDirPath: directory,
	}
	s, err := grypeDB.NewWriter(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := s.SetDBMetadata(); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	return &writer{
		dbPath:               cfg.DBFilePath(),
		failOnMissingFixDate: failOnMissingFixDate,
		providerCache:        make(map[string]grypeDB.Provider),
		store:                s,
		states:               states,
		severityCache:        make(map[string]grypeDB.Severity),
	}, nil
}

func (w writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != grypeDB.ModelVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", grypeDB.ModelVersion, entry.DBSchemaVersion)
		}

		switch row := entry.Data.(type) {
		case transformers.RelatedEntries:
			if err := w.writeEntry(row); err != nil {
				return fmt.Errorf("unable to write entry to store: %w", err)
			}
		default:
			return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
		}
	}

	return nil
}

func (w *writer) writeEntry(entry transformers.RelatedEntries) error {
	log.WithFields("entry", entry.String()).Trace("writing entry")

	if entry.VulnerabilityHandle != nil {
		w.fillInMissingSeverity(entry.VulnerabilityHandle)

		if err := w.store.AddVulnerabilities(entry.VulnerabilityHandle); err != nil {
			return fmt.Errorf("unable to write vulnerability to store: %w", err)
		}
	}

	if entry.Provider != nil {
		if err := w.store.AddProvider(*entry.Provider); err != nil {
			return fmt.Errorf("unable to write provider to store: %w", err)
		}
	}

	for i := range entry.Related {
		if err := w.writeRelatedEntry(entry.VulnerabilityHandle, entry.Related[i]); err != nil {
			return err
		}
	}

	return nil
}

func (w *writer) writeRelatedEntry(vulnHandle *grypeDB.VulnerabilityHandle, related any) error {
	switch row := related.(type) {
	case grypeDB.AffectedPackageHandle:
		return w.writeAffectedPackage(vulnHandle, row)
	case grypeDB.AffectedCPEHandle:
		return w.writeAffectedCPE(vulnHandle, row)
	case grypeDB.KnownExploitedVulnerabilityHandle:
		return w.store.AddKnownExploitedVulnerabilities(&row)
	case grypeDB.UnaffectedPackageHandle:
		return w.writeUnaffectedPackage(vulnHandle, row)
	case grypeDB.UnaffectedCPEHandle:
		return w.writeUnaffectedCPE(vulnHandle, row)
	case grypeDB.EpssHandle:
		return w.store.AddEpss(&row)
	case grypeDB.CWEHandle:
		return w.store.AddCWE(&row)
	default:
		return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
	}
}

func (w *writer) writeAffectedPackage(vulnHandle *grypeDB.VulnerabilityHandle, row grypeDB.AffectedPackageHandle) error {
	if vulnHandle != nil {
		row.VulnerabilityID = vulnHandle.ID
	} else {
		log.WithFields("package", row.Package).Warn("affected package entry does not have a vulnerability ID")
	}

	if w.failOnMissingFixDate {
		if err := ensureFixDates(&row); err != nil {
			fields := logger.Fields{
				"pkg": row.Package,
			}
			if vulnHandle != nil {
				fields["vulnerability"] = vulnHandle.Name
			}
			if row.BlobValue != nil {
				fields["ranges"] = row.BlobValue.String()
			}
			if row.OperatingSystem != nil {
				fields["os"] = row.OperatingSystem
			}
			log.WithFields(fields).Error("fix date validation failed")
			return fmt.Errorf("unable to validate fix dates: %w", err)
		}
	}

	if err := w.store.AddAffectedPackages(&row); err != nil {
		return fmt.Errorf("unable to write affected-package to store: %w", err)
	}
	return nil
}

func (w *writer) writeAffectedCPE(vulnHandle *grypeDB.VulnerabilityHandle, row grypeDB.AffectedCPEHandle) error {
	if vulnHandle != nil {
		row.VulnerabilityID = vulnHandle.ID
	} else {
		log.WithFields("cpe", row.CPE).Warn("affected CPE entry does not have a vulnerability ID")
	}
	if err := w.store.AddAffectedCPEs(&row); err != nil {
		return fmt.Errorf("unable to write affected-cpe to store: %w", err)
	}
	return nil
}

func (w *writer) writeUnaffectedPackage(vulnHandle *grypeDB.VulnerabilityHandle, row grypeDB.UnaffectedPackageHandle) error {
	if vulnHandle != nil {
		row.VulnerabilityID = vulnHandle.ID
	} else {
		log.WithFields("package", row.Package).Warn("unaffected package entry does not have a vulnerability ID")
	}
	if err := w.store.AddUnaffectedPackages(&row); err != nil {
		return fmt.Errorf("unable to write unaffected-package to store: %w", err)
	}
	return nil
}

func (w *writer) writeUnaffectedCPE(vulnHandle *grypeDB.VulnerabilityHandle, row grypeDB.UnaffectedCPEHandle) error {
	if vulnHandle != nil {
		row.VulnerabilityID = vulnHandle.ID
	} else {
		log.WithFields("cpe", row.CPE).Warn("unaffected CPE entry does not have a vulnerability ID")
	}
	if err := w.store.AddUnaffectedCPEs(&row); err != nil {
		return fmt.Errorf("unable to write unaffected-cpe to store: %w", err)
	}
	return nil
}

// fillInMissingSeverity will add a severity entry to the vulnerability record if it is missing, empty, or "unknown".
// The upstream NVD record is used to fill in these missing values. Note that the NVD provider is always guaranteed
// to be processed first before other providers.
func (w *writer) fillInMissingSeverity(handle *grypeDB.VulnerabilityHandle) {
	if handle == nil {
		return
	}

	blob := handle.BlobValue
	if blob == nil {
		return
	}

	id := strings.ToLower(blob.ID)
	isCVE := strings.HasPrefix(id, "cve-")
	if strings.ToLower(handle.ProviderID) == "nvd" && isCVE {
		if len(blob.Severities) > 0 {
			w.severityCache[id] = blob.Severities[0]
		}
		return
	}

	if !isCVE {
		return
	}

	// parse all string severities and remove all unknown values
	sevs := filterUnknownSeverities(blob.Severities)

	topSevStr := "none"
	if len(sevs) > 0 {
		switch v := sevs[0].Value.(type) {
		case string:
			topSevStr = v
		case fmt.Stringer:
			topSevStr = v.String()
		default:
			topSevStr = fmt.Sprintf("%v", sevs[0].Value)
		}
	}

	if len(sevs) > 0 {
		return // already has a severity, don't normalize
	}

	// add the top NVD severity value
	nvdSev, ok := w.severityCache[id]
	if !ok {
		log.WithFields("id", blob.ID).Trace("unable to find NVD severity")
		return
	}

	log.WithFields("id", blob.ID, "provider", handle.Provider, "sev-from", topSevStr, "sev-to", nvdSev).Trace("overriding irrelevant severity with data from NVD record")
	sevs = append([]grypeDB.Severity{nvdSev}, sevs...)
	handle.BlobValue.Severities = sevs
}

func (w writer) Close() error {
	if err := w.store.Close(); err != nil {
		return fmt.Errorf("unable to close store: %w", err)
	}

	log.WithFields("path", w.dbPath).Info("database created")

	return nil
}

func filterUnknownSeverities(sevs []grypeDB.Severity) []grypeDB.Severity {
	var out []grypeDB.Severity
	for _, s := range sevs {
		if isKnownSeverity(s) {
			out = append(out, s)
		}
	}
	return out
}

func isKnownSeverity(s grypeDB.Severity) bool {
	switch v := s.Value.(type) {
	case string:
		return v != "" && strings.ToLower(v) != "unknown"
	default:
		return v != nil
	}
}

func ensureFixDates(row *grypeDB.AffectedPackageHandle) error {
	if row.BlobValue == nil {
		return nil
	}

	for _, r := range row.BlobValue.Ranges {
		if r.Fix == nil {
			continue
		}
		if !isFixVersion(r.Fix.Version) || r.Fix.State != grypeDB.FixedStatus {
			continue
		}
		if r.Fix.Detail == nil || r.Fix.Detail.Available == nil || r.Fix.Detail.Available.Date == nil {
			return fmt.Errorf("missing fix date for version %q", r.Fix.Version)
		}
		if r.Fix.Detail.Available.Date.IsZero() {
			return fmt.Errorf("zero fix date for version %q", r.Fix.Version)
		}
	}
	return nil
}

func isFixVersion(v string) bool {
	return v != "" && v != "0" && strings.ToLower(v) != "none"
}
