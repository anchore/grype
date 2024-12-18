package v6

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

type AffectedCPEStoreWriter interface {
	AddAffectedCPEs(packages ...*AffectedCPEHandle) error
}

type AffectedCPEStoreReader interface {
	GetAffectedCPEs(cpe *cpe.Attributes, config *GetAffectedCPEOptions) ([]AffectedCPEHandle, error)
}

type GetAffectedCPEOptions struct {
	PreloadCPE           bool
	PreloadVulnerability bool
	PreloadBlob          bool
	Vulnerabilities      []VulnerabilitySpecifier
	Limit                int
}

type affectedCPEStore struct {
	db        *gorm.DB
	blobStore *blobStore
}

func newAffectedCPEStore(db *gorm.DB, bs *blobStore) *affectedCPEStore {
	return &affectedCPEStore{
		db:        db,
		blobStore: bs,
	}
}

// AddAffectedCPEs adds one or more affected CPEs to the store
func (s *affectedCPEStore) AddAffectedCPEs(packages ...*AffectedCPEHandle) error {
	for _, pkg := range packages {
		if err := s.blobStore.addBlobable(pkg); err != nil {
			return fmt.Errorf("unable to add affected package blob: %w", err)
		}

		if err := s.db.Create(pkg).Error; err != nil {
			return fmt.Errorf("unable to add affected CPE: %w", err)
		}
	}
	return nil
}

// GetAffectedCPEs retrieves a single AffectedCPEHandle by one or more CPE fields (not including version and update fields, which are ignored)
func (s *affectedCPEStore) GetAffectedCPEs(cpe *cpe.Attributes, config *GetAffectedCPEOptions) ([]AffectedCPEHandle, error) {
	if config == nil {
		config = &GetAffectedCPEOptions{}
	}

	fields := make(logger.Fields)
	if cpe == nil {
		fields["cpe"] = "any"
	} else {
		fields["cpe"] = cpe.String()
	}
	start := time.Now()
	defer func() {
		fields["duration"] = time.Since(start)
		log.WithFields(fields).Trace("fetched affected CPE record")
	}()

	query := s.handleCPE(s.db, cpe)

	var err error
	query, err = s.handleVulnerabilityOptions(query, config.Vulnerabilities)
	if err != nil {
		return nil, err
	}

	query = s.handlePreload(query, *config)

	var models []AffectedCPEHandle

	var results []*AffectedCPEHandle
	if err := query.FindInBatches(&results, batchSize, func(_ *gorm.DB, _ int) error { // nolint:dupl
		if config.PreloadBlob {
			var blobs []blobable
			for _, r := range results {
				blobs = append(blobs, r)
			}
			if err := s.blobStore.attachBlobValue(blobs...); err != nil {
				return fmt.Errorf("unable to attach blobs: %w", err)
			}
		}

		if config.PreloadVulnerability {
			var vulns []blobable
			for _, r := range results {
				if r.Vulnerability != nil {
					vulns = append(vulns, r.Vulnerability)
				}
			}
			if err := s.blobStore.attachBlobValue(vulns...); err != nil {
				return fmt.Errorf("unable to attach vulnerability blob: %w", err)
			}
		}

		for _, r := range results {
			models = append(models, *r)
		}

		if config.Limit > 0 && len(models) >= config.Limit {
			return ErrLimitReached
		}

		return nil
	}).Error; err != nil {
		return models, fmt.Errorf("unable to fetch affected CPE records: %w", err)
	}

	return models, nil
}

func (s *affectedCPEStore) handleCPE(query *gorm.DB, c *cpe.Attributes) *gorm.DB {
	if c == nil {
		return query
	}
	query = query.Joins("JOIN cpes ON cpes.id = affected_cpe_handles.cpe_id")

	return handleCPEOptions(query, c)
}

func (s *affectedCPEStore) handleVulnerabilityOptions(query *gorm.DB, configs []VulnerabilitySpecifier) (*gorm.DB, error) {
	if len(configs) == 0 {
		return query, nil
	}

	query = query.Joins("JOIN vulnerability_handles ON affected_cpe_handles.vulnerability_id = vulnerability_handles.id")

	return handleVulnerabilityOptions(s.db, query, configs...)
}

func (s *affectedCPEStore) handlePreload(query *gorm.DB, config GetAffectedCPEOptions) *gorm.DB {
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
