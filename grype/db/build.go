package db

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/entry"
	grypeDBv5 "github.com/anchore/grype/grype/db/v5"
	v5 "github.com/anchore/grype/grype/db/v5/build"
	grypeDBv6 "github.com/anchore/grype/grype/db/v6"
	v6 "github.com/anchore/grype/grype/db/v6/build"
	"github.com/anchore/grype/grype/db/v6/build/transformers/nvd"
	"github.com/anchore/grype/internal/log"
)

// DefaultBatchSize is the default number of database operations to batch together
// before flushing to disk. This value balances throughput with memory usage.
const DefaultBatchSize = 2000

type BuildConfig struct {
	SchemaVersion        int
	Directory            string
	States               provider.States
	Timestamp            time.Time
	IncludeCPEParts      []string
	InferNVDFixVersions  bool
	Hydrate              bool
	FailOnMissingFixDate bool // any fixes found without at least one available date will cause a build failure
	BatchSize            int  // number of operations to batch before committing
	SQLiteCacheSizeKiB   int  // SQLite page cache size (in KiB) used while writing the DB; zero means the built-in default (1 GiB)

	// ReconcileCNA combines each NVD record with the CNA data in the `cve5` provider's CVE 5 record. It is only
	// supported for schema 6 and requires `cve5` and `nvd` provider states.
	ReconcileCNA bool
}

const (
	cve5Provider = "cve5"
	nvdProvider  = "nvd"

	// maxCVE5Lag is how much older the `cve5` input may be than the `nvd` input before reconciliation refuses it
	maxCVE5Lag = 48 * time.Hour
)

func Build(cfg BuildConfig) error {
	log.WithFields(
		"schema", cfg.SchemaVersion,
		"build-directory", cfg.Directory,
		"providers", cfg.States.Names()).
		Info("building database")

	if cfg.ReconcileCNA && cfg.SchemaVersion != grypeDBv6.ModelVersion {
		return fmt.Errorf("CNA reconciliation is only supported for schema version %d, not %d", grypeDBv6.ModelVersion, cfg.SchemaVersion)
	}

	var cnaIndex *nvd.Index
	if cfg.ReconcileCNA {
		var err error
		cnaIndex, err = readCNAIndex(cfg.States)
		if err != nil {
			return err
		}
	}

	processors, nvdConfig, err := getProcessors(cfg, cnaIndex)
	if err != nil {
		return err
	}

	writer, err := getWriter(cfg)
	if err != nil {
		return err
	}

	var openers []providerResults
	for _, sd := range cfg.States {
		if sd.Provider == cve5Provider {
			// cve5 is never processed as a provider of its own: when reconciling, it was read above, and otherwise it is unused
			continue
		}
		sdOpeners, count, err := entry.Openers(sd.Store, sd.ResultPaths())
		if err != nil {
			return fmt.Errorf("failed to open provider result files: %w", err)
		}
		openers = append(openers, providerResults{
			openers:  sdOpeners,
			provider: sd,
			count:    count,
		})
	}

	if err := build(openers, writer, processors...); err != nil {
		return err
	}

	if cnaIndex != nil {
		if err := writeCVE5Only(cnaIndex, nvdConfig, cfg.States, writer); err != nil {
			return err
		}
	}

	if err := writer.Close(); err != nil {
		return err
	}

	if cfg.Hydrate && cfg.SchemaVersion > 5 {
		if err := hydrate(cfg); err != nil {
			return err
		}
	}

	return nil
}

type providerResults struct {
	openers  <-chan entry.Opener
	provider provider.State
	count    int64
}

// getProcessors returns the processors for the schema, and for schema 6 the NVD transformer's config, which the
// leftover CVE 5 records are written with.
func getProcessors(cfg BuildConfig, cnaIndex *nvd.Index) ([]data.Processor, nvd.Config, error) {
	switch cfg.SchemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.Processors(v5.NewConfig(v5.WithCPEParts(cfg.IncludeCPEParts), v5.WithInferNVDFixVersions(cfg.InferNVDFixVersions))), nvd.Config{}, nil
	case grypeDBv6.ModelVersion:
		v6Config := v6.NewConfig(v6.WithCPEParts(cfg.IncludeCPEParts), v6.WithInferNVDFixVersions(cfg.InferNVDFixVersions), v6.WithCNAIndex(cnaIndex))
		return v6.Processors(v6Config), v6Config.NVD, nil
	default:
		return nil, nvd.Config{}, fmt.Errorf("unable to create processor: unsupported schema version: %+v", cfg.SchemaVersion)
	}
}

// readCNAIndex indexes the `cve5` provider's records, after checking that the input is usable: `cve5` and `nvd` are
// both present, `cve5` is not much older than `nvd`, and `cve5` holds records.
func readCNAIndex(states provider.States) (*nvd.Index, error) {
	cve5, nvdState := findState(states, cve5Provider), findState(states, nvdProvider)
	if cve5 == nil {
		return nil, fmt.Errorf("CNA reconciliation is enabled but there is no %q provider input", cve5Provider)
	}
	if nvdState == nil {
		return nil, fmt.Errorf("CNA reconciliation is enabled but there is no %q provider input", nvdProvider)
	}

	if nvdState.Timestamp.Sub(cve5.Timestamp) > maxCVE5Lag {
		return nil, fmt.Errorf(
			"%q input is more than %s older than %q input: %q captured %s, %q captured %s",
			cve5Provider, maxCVE5Lag, nvdProvider,
			cve5Provider, cve5.Timestamp.Format(time.RFC3339),
			nvdProvider, nvdState.Timestamp.Format(time.RFC3339),
		)
	}

	openers, _, err := entry.Openers(cve5.Store, cve5.ResultPaths())
	if err != nil {
		return nil, fmt.Errorf("failed to open %q provider result files: %w", cve5Provider, err)
	}

	idx, err := nvd.NewIndex(openers)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q provider records: %w", cve5Provider, err)
	}

	if idx.Count() == 0 {
		return nil, fmt.Errorf("%q input holds no records", cve5Provider)
	}

	log.WithFields("records", idx.Count()).Debug("read CVE 5 records for CNA reconciliation")
	return idx, nil
}

func findState(states provider.States, name string) *provider.State {
	for i := range states {
		if states[i].Provider == name {
			return &states[i]
		}
	}
	return nil
}

// writeCVE5Only writes the CVEs that have a CVE 5 record and no NVD record, under the `nvd` provider.
func writeCVE5Only(idx *nvd.Index, nvdConfig nvd.Config, states provider.States, writer data.Writer) error {
	nvdState := findState(states, nvdProvider)
	if nvdState == nil {
		return fmt.Errorf("no %q provider input to write CVE 5 records under", nvdProvider)
	}

	for _, record := range idx.Leftovers() {
		entries := nvd.TransformCVE5Only(nvdConfig, record, *nvdState)
		if len(entries) == 0 {
			continue
		}
		if err := writer.Write(entries...); err != nil {
			return fmt.Errorf("failed to write CVE 5 record %q to the DB: %w", record.ID, err)
		}
	}
	return nil
}

func getWriter(cfg BuildConfig) (data.Writer, error) {
	// Use default if not configured
	batchSize := cfg.BatchSize
	if batchSize == 0 {
		batchSize = DefaultBatchSize
	}

	switch cfg.SchemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.NewWriter(cfg.Directory, cfg.Timestamp, cfg.States, batchSize, v5.WithSQLiteCacheSizeKiB(cfg.SQLiteCacheSizeKiB))
	case grypeDBv6.ModelVersion:
		options := []v6.WriterOption{v6.WithSQLiteCacheSizeKiB(cfg.SQLiteCacheSizeKiB)}
		if cfg.ReconcileCNA {
			options = append(options, v6.WithNVDPackageMerge())
		}
		return v6.NewWriter(cfg.Directory, cfg.States, cfg.FailOnMissingFixDate, batchSize, options...)
	default:
		return nil, fmt.Errorf("unable to create writer: unsupported schema version: %+v", cfg.SchemaVersion)
	}
}

func build(results []providerResults, writer data.Writer, processors ...data.Processor) error { // nolint:funlen
	lastUpdate := time.Now()
	var totalRecords int
	for _, result := range results {
		totalRecords += int(result.count)
	}
	log.WithFields("total", humanize.Comma(int64(totalRecords))).Info("processing all records")

	// for exponential moving average, choose an alpha between 0 and 1, where 1 biases towards the most recent sample
	// and 0 biases towards the average of all samples.
	rateWindow := newEMA(0.4)

	var recordsProcessed, recordsObserved, dropped int
	droppedElementsByProvider := make(map[string]int)
	droppedSchemaElements := make(map[string]int)

	for _, result := range results {
		log.WithFields("provider", result.provider.Provider, "total", humanize.Comma(result.count)).Info("processing provider records")
		providerRecordsObserved := 0
		recordsObservedInStatusCycle := 0
		for opener := range result.openers {
			providerRecordsObserved++
			recordsObserved++
			recordsObservedInStatusCycle++
			var processor data.Processor

			if time.Since(lastUpdate) > 3*time.Second {
				r := recordsPerSecond(recordsObservedInStatusCycle, lastUpdate)
				rateWindow.Add(r)

				log.WithFields(
					"provider", fmt.Sprintf("%q %1.0f/s (%1.2f%%)", result.provider.Provider, r, percent(providerRecordsObserved, int(result.count))),
					"overall", fmt.Sprintf("%1.2f%%", percent(recordsObserved, totalRecords)),
					"eta", eta(recordsObserved, totalRecords, rateWindow.Average()).String(),
				).Debug("status")
				lastUpdate = time.Now()
				recordsObservedInStatusCycle = 0
			}

			f, err := opener.Open()
			if err != nil {
				return fmt.Errorf("failed to open cache entry %q: %w", opener.String(), err)
			}
			envelope, err := unmarshal.Envelope(f)
			_ = f.Close()
			if err != nil {
				return fmt.Errorf("failed to unmarshal cache entry %q: %w", opener.String(), err)
			}

			for _, candidate := range processors {
				if candidate.IsSupported(envelope.Schema) {
					processor = candidate
					break
				}
			}
			if processor == nil {
				droppedElementsByProvider[result.provider.Provider]++
				droppedSchemaElements[envelope.Schema]++
				dropped++
				continue
			}
			recordsProcessed++

			entries, err := processor.Process(bytes.NewReader(envelope.Item), result.provider)
			if err != nil {
				return fmt.Errorf("failed to process cache entry %q: %w", opener.String(), err)
			}

			if err := writer.Write(entries...); err != nil {
				return fmt.Errorf("failed to write records to the DB for cache entry %q: %w", opener.String(), err)
			}
		}
	}

	logDropped(droppedElementsByProvider, droppedSchemaElements)

	log.WithFields("processed", recordsProcessed, "dropped", dropped, "observed", recordsObserved).Debugf("wrote all provider state")

	if recordsProcessed == 0 {
		return fmt.Errorf("no records were processed")
	}

	return nil
}

func hydrate(cfg BuildConfig) error {
	hydrator := grypeDBv6.Hydrater()
	fs := afero.NewOsFs()

	if err := hydrator(cfg.Directory); err != nil {
		return fmt.Errorf("failed to hydrate db: %w", err)
	}

	doc, err := grypeDBv6.WriteImportMetadata(fs, cfg.Directory, "grype db build")
	if err != nil {
		return fmt.Errorf("failed to write checksums file: %w", err)
	}

	log.WithFields("digest", doc.Digest).Trace("captured DB digest")

	return nil
}

func logDropped(droppedElementsByProvider, droppedSchemaElements map[string]int) {
	sortedKeys := func(m map[string]int) []string {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	sortedProviders := sortedKeys(droppedElementsByProvider)
	for _, p := range sortedProviders {
		log.WithFields("provider", p, "count", droppedElementsByProvider[p]).Warn("dropped records for provider")
	}

	sortedSchemas := sortedKeys(droppedSchemaElements)
	for _, s := range sortedSchemas {
		log.WithFields("schema", s, "count", droppedSchemaElements[s]).Warn("dropped records by schema")
	}
}

type expMovingAverage struct {
	alpha float64
	value float64
	count int
}

func newEMA(alpha float64) *expMovingAverage {
	return &expMovingAverage{alpha: alpha}
}

func (e *expMovingAverage) Add(sample float64) {
	if e.count == 0 {
		e.value = sample // initialize with the first sample
	} else {
		e.value = e.alpha*sample + (1-e.alpha)*e.value
	}
	e.count++
}

func (e *expMovingAverage) Average() float64 {
	return e.value
}

func recordsPerSecond(idx int, lastUpdate time.Time) float64 {
	sec := time.Since(lastUpdate).Seconds()
	if sec == 0 {
		return 0
	}
	return float64(idx) / sec
}

func percent(idx, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(idx) / float64(total) * 100
}

func eta(idx, total int, rate float64) time.Duration {
	if rate == 0 {
		return 0
	}
	return time.Duration(float64(total-idx)/rate) * time.Second
}
