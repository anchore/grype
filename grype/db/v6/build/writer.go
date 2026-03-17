package v6

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/grype/internal/log"
)

var _ data.Writer = (*writer)(nil)

type writer struct {
	dbPath               string
	failOnMissingFixDate bool
	store                db.ReadWriter
	providerCache        map[string]db.Provider
	states               provider.States
	severityCache        map[string]db.Severity

	// Two-tier batching: parent records (vulnerabilities + providers) and child records (related entries)
	// This maintains FK integrity while maximizing batch sizes
	parentBatchSize int
	childBatchSize  int
	parentBuffer    []func() error
	childBuffer     []func() error
	mu              sync.Mutex // Protect batch state

	// Metrics
	totalParentBatches int
	totalChildBatches  int
}

type ProviderMetadata struct {
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Name              string    `json:"name"`
	LastSuccessfulRun time.Time `json:"lastSuccessfulRun"`
}

func NewWriter(directory string, states provider.States, failOnMissingFixDate bool, batchSize int) (data.Writer, error) {
	cfg := db.Config{
		DBDirPath: directory,
	}
	s, err := db.NewWriter(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create store: %w", err)
	}

	if err := s.SetDBMetadata(); err != nil {
		return nil, fmt.Errorf("unable to set DB ID: %w", err)
	}

	// Use default if not configured
	if batchSize == 0 {
		batchSize = 2000
	}

	return &writer{
		dbPath:               cfg.DBFilePath(),
		failOnMissingFixDate: failOnMissingFixDate,
		providerCache:        make(map[string]db.Provider),
		store:                s,
		states:               states,
		severityCache:        make(map[string]db.Severity),
		parentBatchSize:      batchSize,
		childBatchSize:       batchSize,
		parentBuffer:         make([]func() error, 0, batchSize),
		childBuffer:          make([]func() error, 0, batchSize),
	}, nil
}

func (w *writer) Write(entries ...data.Entry) error {
	for _, entry := range entries {
		if entry.DBSchemaVersion != db.ModelVersion {
			return fmt.Errorf("wrong schema version: want %+v got %+v", db.ModelVersion, entry.DBSchemaVersion)
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

		// Add vulnerability to parent batch
		// CRITICAL: Use pointer directly (not copy) so ID assignment propagates to child operations
		vulnHandle := entry.VulnerabilityHandle
		if err := w.addToParentBatch(func() error {
			return w.store.AddVulnerabilities(vulnHandle)
		}); err != nil {
			return fmt.Errorf("unable to batch vulnerability write: %w", err)
		}
	}

	// Handle providers for entries without vulnerabilities (EPSS, KEV, etc.)
	// AddVulnerabilities() only handles providers implicitly for vulnerability entries
	if entry.Provider != nil && entry.VulnerabilityHandle == nil {
		provider := *entry.Provider
		if err := w.addToParentBatch(func() error {
			return w.store.AddProvider(provider)
		}); err != nil {
			return fmt.Errorf("unable to batch provider write: %w", err)
		}
	}

	// Add all related entries to child batch
	// NOTE: No explicit flush here. Parent batch auto-flushes at threshold.
	// Child batch auto-flush will flush parent first to maintain FK integrity.
	for i := range entry.Related {
		if err := w.writeRelatedEntry(entry.VulnerabilityHandle, entry.Related[i]); err != nil {
			return err
		}
	}

	return nil
}

func (w *writer) writeRelatedEntry(vulnHandle *db.VulnerabilityHandle, related any) error {
	switch row := related.(type) {
	case db.AffectedPackageHandle:
		return w.writeAffectedPackage(vulnHandle, row)
	case db.AffectedCPEHandle:
		return w.writeAffectedCPE(vulnHandle, row)
	case db.KnownExploitedVulnerabilityHandle:
		// Add KEV to child batch - copy to avoid pointer reuse
		kevHandle := row
		return w.addToChildBatch(func() error {
			handleCopy := kevHandle
			return w.store.AddKnownExploitedVulnerabilities(&handleCopy)
		})
	case db.UnaffectedPackageHandle:
		return w.writeUnaffectedPackage(vulnHandle, row)
	case db.UnaffectedCPEHandle:
		return w.writeUnaffectedCPE(vulnHandle, row)
	case db.EpssHandle:
		// Add EPSS to child batch - copy to avoid pointer reuse
		epssHandle := row
		return w.addToChildBatch(func() error {
			handleCopy := epssHandle
			return w.store.AddEpss(&handleCopy)
		})
	case db.CWEHandle:
		// Add CWE to child batch - copy to avoid pointer reuse
		cweHandle := row
		return w.addToChildBatch(func() error {
			handleCopy := cweHandle
			return w.store.AddCWE(&handleCopy)
		})
	case db.OperatingSystemEOLHandle:
		// Add OS EOL to child batch - copy to avoid pointer reuse
		eolHandle := row
		return w.addToChildBatch(func() error {
			handleCopy := eolHandle
			return w.writeOperatingSystemEOL(handleCopy)
		})
	default:
		return fmt.Errorf("data entry is not of type vulnerability, vulnerability metadata, or exclusion: %T", row)
	}
}

func (w *writer) writeAffectedPackage(vulnHandle *db.VulnerabilityHandle, row db.AffectedPackageHandle) error {
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

	// Add affected package to child batch - defer VulnerabilityID assignment until flush
	pkgHandle := row
	return w.addToChildBatch(func() error {
		handleCopy := pkgHandle
		if vulnHandle != nil {
			handleCopy.VulnerabilityID = vulnHandle.ID
		} else {
			log.WithFields("package", handleCopy.Package).Warn("affected package entry does not have a vulnerability ID")
		}
		return w.store.AddAffectedPackages(&handleCopy)
	})
}

func (w *writer) writeAffectedCPE(vulnHandle *db.VulnerabilityHandle, row db.AffectedCPEHandle) error {
	// Add affected CPE to child batch - defer VulnerabilityID assignment until flush
	// when the parent vulnerability has been written and ID is assigned
	cpeHandle := row
	return w.addToChildBatch(func() error {
		handleCopy := cpeHandle
		if vulnHandle != nil {
			handleCopy.VulnerabilityID = vulnHandle.ID
		} else {
			log.WithFields("cpe", handleCopy.CPE).Warn("affected CPE entry does not have a vulnerability ID")
		}
		return w.store.AddAffectedCPEs(&handleCopy)
	})
}

func (w *writer) writeUnaffectedPackage(vulnHandle *db.VulnerabilityHandle, row db.UnaffectedPackageHandle) error {
	// Add unaffected package to child batch - defer VulnerabilityID assignment until flush
	pkgHandle := row
	return w.addToChildBatch(func() error {
		handleCopy := pkgHandle
		if vulnHandle != nil {
			handleCopy.VulnerabilityID = vulnHandle.ID
		} else {
			log.WithFields("package", handleCopy.Package).Warn("unaffected package entry does not have a vulnerability ID")
		}
		return w.store.AddUnaffectedPackages(&handleCopy)
	})
}

func (w *writer) writeUnaffectedCPE(vulnHandle *db.VulnerabilityHandle, row db.UnaffectedCPEHandle) error {
	// Add unaffected CPE to child batch - defer VulnerabilityID assignment until flush
	cpeHandle := row
	return w.addToChildBatch(func() error {
		handleCopy := cpeHandle
		if vulnHandle != nil {
			handleCopy.VulnerabilityID = vulnHandle.ID
		} else {
			log.WithFields("cpe", handleCopy.CPE).Warn("unaffected CPE entry does not have a vulnerability ID")
		}
		return w.store.AddUnaffectedCPEs(&handleCopy)
	})
}

// fillInMissingSeverity will add a severity entry to the vulnerability record if it is missing, empty, or "unknown".
// The upstream NVD record is used to fill in these missing values. Note that the NVD provider is always guaranteed
// to be processed first before other providers.
func (w *writer) fillInMissingSeverity(handle *db.VulnerabilityHandle) {
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
	sevs = append([]db.Severity{nvdSev}, sevs...)
	handle.BlobValue.Severities = sevs
}

// addToParentBatch adds an operation to parent buffer and flushes when threshold reached
func (w *writer) addToParentBatch(op func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.parentBuffer = append(w.parentBuffer, op)

	// Flush parent batch when it reaches threshold to limit memory usage
	if len(w.parentBuffer) >= w.parentBatchSize {
		return w.flushParentBatchLocked()
	}
	return nil
}

// addToChildBatch adds an operation to child buffer and flushes when threshold reached
func (w *writer) addToChildBatch(op func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.childBuffer = append(w.childBuffer, op)

	// When child buffer is full, flush BOTH buffers (parents first for FK integrity)
	if len(w.childBuffer) >= w.childBatchSize {
		// Flush parents first to ensure IDs are assigned for children to reference
		if err := w.flushParentBatchLocked(); err != nil {
			return err
		}
		// Then flush children
		return w.flushChildBatchLocked()
	}
	return nil
}

// flushParentBatch executes all pending parent operations in batches of parentBatchSize
func (w *writer) flushParentBatch() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushParentBatchLocked()
}

// flushParentBatchLocked executes all pending parent operations (must be called with lock held)
func (w *writer) flushParentBatchLocked() error {
	if len(w.parentBuffer) == 0 {
		return nil
	}

	log.WithFields("total_operations", len(w.parentBuffer), "batch_size", w.parentBatchSize).Debug("flushing parent operations")

	// Execute all accumulated operations
	for j, op := range w.parentBuffer {
		if err := op(); err != nil {
			return fmt.Errorf("parent operation %d failed: %w", j, err)
		}
	}

	w.totalParentBatches++
	w.parentBuffer = w.parentBuffer[:0]
	return nil
}

// flushChildBatch executes all pending child operations in batches of childBatchSize
func (w *writer) flushChildBatch() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushChildBatchLocked()
}

// flushChildBatchLocked executes all pending child operations (must be called with lock held)
func (w *writer) flushChildBatchLocked() error {
	if len(w.childBuffer) == 0 {
		return nil
	}

	log.WithFields("total_operations", len(w.childBuffer), "batch_size", w.childBatchSize).Debug("flushing child operations")

	// Execute all accumulated operations
	for j, op := range w.childBuffer {
		if err := op(); err != nil {
			return fmt.Errorf("child operation %d failed: %w", j, err)
		}
	}

	w.totalChildBatches++
	w.childBuffer = w.childBuffer[:0]
	return nil
}

func (w *writer) Close() error {
	// Flush any remaining batched operations (both parent and child)
	if err := w.flushParentBatch(); err != nil {
		return fmt.Errorf("unable to flush parent batch: %w", err)
	}
	if err := w.flushChildBatch(); err != nil {
		return fmt.Errorf("unable to flush child batch: %w", err)
	}

	if err := w.store.Close(); err != nil {
		return fmt.Errorf("unable to close store: %w", err)
	}

	log.WithFields(
		"path", w.dbPath,
		"parent_batches", w.totalParentBatches,
		"child_batches", w.totalChildBatches,
	).Info("database created")

	return nil
}

func filterUnknownSeverities(sevs []db.Severity) []db.Severity {
	var out []db.Severity
	for _, s := range sevs {
		if isKnownSeverity(s) {
			out = append(out, s)
		}
	}
	return out
}

func isKnownSeverity(s db.Severity) bool {
	switch v := s.Value.(type) {
	case string:
		return v != "" && strings.ToLower(v) != "unknown"
	default:
		return v != nil
	}
}

func ensureFixDates(row *db.AffectedPackageHandle) error {
	if row.BlobValue == nil {
		return nil
	}

	for _, r := range row.BlobValue.Ranges {
		if r.Fix == nil {
			continue
		}
		if !isFixVersion(r.Fix.Version) || r.Fix.State != db.FixedStatus {
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

func (w *writer) writeOperatingSystemEOL(row db.OperatingSystemEOLHandle) error {
	spec := db.OSSpecifier{
		Name:         row.Name,
		MajorVersion: row.MajorVersion,
		MinorVersion: row.MinorVersion,
		LabelVersion: row.Codename,
	}

	updated, err := w.store.UpdateOperatingSystemEOL(spec, row.EOLDate, row.EOASDate)
	if err != nil {
		return fmt.Errorf("unable to update OS EOL data: %w", err)
	}

	if updated == 0 {
		log.WithFields("os", row.String()).Trace("no OS record found to update with EOL data")
	}

	return nil
}
