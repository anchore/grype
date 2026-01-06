package db

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/spf13/afero"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/db/provider/entry"
	"github.com/anchore/grype/grype/db/provider/unmarshal"
	grypeDBv5 "github.com/anchore/grype/grype/db/v5"
	v5 "github.com/anchore/grype/grype/db/v5/build"
	grypeDBv6 "github.com/anchore/grype/grype/db/v6"
	v6 "github.com/anchore/grype/grype/db/v6/build"
	"github.com/anchore/grype/internal/log"
)

type BuildConfig struct {
	SchemaVersion        int
	Directory            string
	States               provider.States
	Timestamp            time.Time
	IncludeCPEParts      []string
	InferNVDFixVersions  bool
	Hydrate              bool
	FailOnMissingFixDate bool // any fixes found without at least one available date will cause a build failure
}

func Build(cfg BuildConfig) error {
	log.WithFields(
		"schema", cfg.SchemaVersion,
		"build-directory", cfg.Directory,
		"providers", cfg.States.Names()).
		Info("building database")

	processors, err := getProcessors(cfg)
	if err != nil {
		return err
	}

	writer, err := getWriter(cfg)
	if err != nil {
		return err
	}

	var openers []providerResults
	for _, sd := range cfg.States {
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

func getProcessors(cfg BuildConfig) ([]data.Processor, error) {
	switch cfg.SchemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.Processors(v5.NewConfig(v5.WithCPEParts(cfg.IncludeCPEParts), v5.WithInferNVDFixVersions(cfg.InferNVDFixVersions))), nil
	case grypeDBv6.ModelVersion:
		return v6.Processors(v6.NewConfig(v6.WithCPEParts(cfg.IncludeCPEParts), v6.WithInferNVDFixVersions(cfg.InferNVDFixVersions))), nil
	default:
		return nil, fmt.Errorf("unable to create processor: unsupported schema version: %+v", cfg.SchemaVersion)
	}
}

func getWriter(cfg BuildConfig) (data.Writer, error) {
	switch cfg.SchemaVersion {
	case grypeDBv5.SchemaVersion:
		return v5.NewWriter(cfg.Directory, cfg.Timestamp, cfg.States)
	case grypeDBv6.ModelVersion:
		return v6.NewWriter(cfg.Directory, cfg.States, cfg.FailOnMissingFixDate)
	default:
		return nil, fmt.Errorf("unable to create writer: unsupported schema version: %+v", cfg.SchemaVersion)
	}
}

func build(results []providerResults, writer data.Writer, processors ...data.Processor) error {
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
