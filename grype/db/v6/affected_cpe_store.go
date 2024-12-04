package v6

import (
	"fmt"

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
	Vulnerability        *VulnerabilitySpecifier
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
	log.WithFields(fields).Trace("fetching AffectedCPE record")

	query := s.handleCPE(s.db, cpe)

	var err error
	query, err = s.handleVulnerabilityOptions(query, config.Vulnerability)
	if err != nil {
		return nil, err
	}

	query = s.handlePreload(query, *config)

	var pkgs []AffectedCPEHandle
	if err = query.Find(&pkgs).Error; err != nil {
		return nil, fmt.Errorf("unable to fetch affected package record: %w", err)
	}

	if config.PreloadBlob {
		for i := range pkgs {
			err := s.blobStore.attachBlobValue(&pkgs[i])
			if err != nil {
				return nil, fmt.Errorf("unable to attach blob %#v: %w", pkgs[i], err)
			}
		}
	}

	if config.PreloadVulnerability {
		for i := range pkgs {
			err := s.blobStore.attachBlobValue(pkgs[i].Vulnerability)
			if err != nil {
				return nil, fmt.Errorf("unable to attach vulnerability blob %#v: %w", pkgs[i], err)
			}
		}
	}

	return pkgs, nil
}

func (s *affectedCPEStore) handleCPE(query *gorm.DB, c *cpe.Attributes) *gorm.DB {
	if c == nil {
		return query
	}
	query = query.Joins("JOIN cpes ON cpes.id = affected_cpe_handles.cpe_id")

	return handleCPEOptions(query, c)
}

func (s *affectedCPEStore) handleVulnerabilityOptions(query *gorm.DB, config *VulnerabilitySpecifier) (*gorm.DB, error) {
	if config == nil {
		return query, nil
	}

	query = query.Joins("JOIN vulnerability_handles ON affected_cpe_handles.vulnerability_id = vulnerability_handles.id")

	return handleVulnerabilityOptions(s.db, query, config)
}

func (s *affectedCPEStore) handlePreload(query *gorm.DB, config GetAffectedCPEOptions) *gorm.DB {
	if config.PreloadCPE {
		query = query.Preload("CPE")
	}

	if config.PreloadVulnerability {
		query = query.Preload("Vulnerability").Preload("Vulnerability.Provider")
	}

	return query
}
