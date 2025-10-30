package v6

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

type cpeHandleStore interface {
	*AffectedCPEHandle | *UnaffectedCPEHandle
}

type cpeHandleAccessor interface {
	getCPEHandle() *cpeHandle
}

type GetCPEOptions struct {
	PreloadCPE            bool
	PreloadVulnerability  bool
	PreloadBlob           bool
	Vulnerabilities       []VulnerabilitySpecifier
	AllowBroadCPEMatching bool
	Limit                 int
}

type cpeStore struct {
	db        *gorm.DB
	blobStore *blobStore
}

func newCPEStore(db *gorm.DB, bs *blobStore) *cpeStore {
	return &cpeStore{
		db:        db,
		blobStore: bs,
	}
}

func addCPEs[T cpeHandleStore](s *cpeStore, packages ...T) error {
	cacheInst, ok := cacheFromContext(s.db.Statement.Context)
	if !ok {
		return fmt.Errorf("unable to fetch CPE cache from context")
	}

	var final []*Cpe
	byCacheKey := make(map[string][]*Cpe)

	for _, p := range packages {
		ch := any(p).(cpeHandleAccessor).getCPEHandle()

		if ch.CPE != nil {
			key := ch.CPE.cacheKey()
			if existingID, ok := cacheInst.getID(ch.CPE); ok {
				// seen in a previous transaction...
				ch.CpeID = existingID
			} else if _, ok := byCacheKey[key]; !ok {
				// not seen within this transaction
				final = append(final, ch.CPE)
			}
			byCacheKey[key] = append(byCacheKey[key], ch.CPE)
		}
	}

	if len(final) == 0 {
		return nil
	}

	if err := s.db.Create(final).Error; err != nil {
		return fmt.Errorf("unable to create CPE records: %w", err)
	}

	// update the cache with the new records
	for _, ref := range final {
		cacheInst.set(ref)
	}

	// update all references with the IDs from the cache
	for _, refs := range byCacheKey {
		for _, ref := range refs {
			id, ok := cacheInst.getID(ref)
			if ok {
				ref.setRowID(id)
			}
		}
	}

	// update the parent objects with the FK ID
	for _, p := range packages {
		ch := any(p).(cpeHandleAccessor).getCPEHandle()
		if ch.CPE != nil {
			ch.CpeID = ch.CPE.ID
		}
	}
	return nil
}

func addCPEHandles[T cpeHandleStore](s *cpeStore, packages ...T) error {
	if err := addCPEs(s, packages...); err != nil {
		return fmt.Errorf("unable to add CPEs from CPE handles: %w", err)
	}

	for _, pkg := range packages {
		if err := s.blobStore.addBlobable(any(pkg).(blobable)); err != nil {
			return fmt.Errorf("unable to add CPE handle blob: %w", err)
		}

		if err := s.db.Omit("CPE").Create(pkg).Error; err != nil {
			return fmt.Errorf("unable to add CPE handles: %w", err)
		}
	}
	return nil
}

func getCPEHandles[T cpeHandleStore]( // nolint:funlen
	s *cpeStore,
	cpe *cpe.Attributes,
	config *GetCPEOptions,
	tableName string,
) ([]T, error) {
	if config == nil {
		config = &GetCPEOptions{}
	}

	fields := make(logger.Fields)
	count := 0
	if cpe == nil {
		fields["cpe"] = "any"
	} else {
		fields["cpe"] = cpe.String()
	}
	start := time.Now()
	defer func() {
		fields["duration"] = time.Since(start)
		fields["records"] = count
		log.WithFields(fields).Trace("fetched CPE record")
	}()

	query := s.handleCPE(s.db.Table(tableName), cpe, config.AllowBroadCPEMatching, tableName)

	var err error
	query, err = s.handleVulnerabilityOptions(query, config.Vulnerabilities, tableName)
	if err != nil {
		return nil, err
	}

	query = s.handlePreload(query, *config)

	var models []T
	var results []T

	if err := query.FindInBatches(&results, batchSize, func(_ *gorm.DB, _ int) error {
		if config.PreloadBlob {
			var blobs []blobable
			for i := range results {
				blobs = append(blobs, any(results[i]).(blobable))
			}
			if err := s.blobStore.attachBlobValue(blobs...); err != nil {
				return fmt.Errorf("unable to attach blobs: %w", err)
			}
		}

		if config.PreloadVulnerability {
			var vulns []blobable
			for i := range results {
				ch := any(results[i]).(cpeHandleAccessor).getCPEHandle()
				if ch.Vulnerability != nil {
					vulns = append(vulns, ch.Vulnerability)
				}
			}
			if err := s.blobStore.attachBlobValue(vulns...); err != nil {
				return fmt.Errorf("unable to attach vulnerability blob: %w", err)
			}
		}

		models = append(models, results...)

		count += len(results)

		if config.Limit > 0 && len(models) >= config.Limit {
			return ErrLimitReached
		}

		return nil
	}).Error; err != nil {
		return models, fmt.Errorf("unable to fetch CPE records: %w", err)
	}

	return models, nil
}

func (s *cpeStore) handleCPE(query *gorm.DB, c *cpe.Attributes, allowBroad bool, tableName string) *gorm.DB {
	if c == nil {
		return query
	}
	query = query.Joins(fmt.Sprintf("JOIN cpes ON cpes.id = %s.cpe_id", tableName))

	return handleCPEOptions(query, c, allowBroad)
}

func (s *cpeStore) handleVulnerabilityOptions(query *gorm.DB, configs []VulnerabilitySpecifier, tableName string) (*gorm.DB, error) {
	if len(configs) == 0 {
		return query, nil
	}

	query = query.Joins(fmt.Sprintf("JOIN vulnerability_handles ON %s.vulnerability_id = vulnerability_handles.id", tableName))

	return handleVulnerabilityOptions(s.db, query, configs...)
}

func (s *cpeStore) handlePreload(query *gorm.DB, config GetCPEOptions) *gorm.DB {
	var limitArgs []interface{}
	if config.Limit > 0 {
		query = query.Limit(config.Limit)
		limitArgs = append(limitArgs, func(db *gorm.DB) *gorm.DB {
			return db.Limit(config.Limit)
		})
	}

	if config.PreloadCPE {
		query = query.Preload("CPE", limitArgs...)
	}

	if config.PreloadVulnerability {
		query = query.Preload("Vulnerability", limitArgs...).Preload("Vulnerability.Provider", limitArgs...)
	}

	return query
}
