package store

import (
	"fmt"
	"sort"

	"github.com/go-test/deep"
	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
	v2 "github.com/anchore/grype/grype/db/v2"
	"github.com/anchore/grype/grype/db/v2/store/model"
	"github.com/anchore/grype/internal"
	_ "github.com/anchore/sqlite" // provide the sqlite dialect to gorm via import
)

// store holds an instance of the database connection
type store struct {
	db *gorm.DB
}

// New creates a new instance of the store.
func New(dbFilePath string, overwrite bool) (v2.Store, error) {
	db, err := gormadapter.Open(dbFilePath, overwrite)
	if err != nil {
		return nil, err
	}
	if overwrite {
		// TODO: automigrate could write to the database,
		//  we should be validating the database is the correct database based on the version in the ID table before
		//  automigrating
		if err := db.AutoMigrate(&model.IDModel{}); err != nil {
			return nil, fmt.Errorf("unable to migrate ID model: %w", err)
		}
		if err := db.AutoMigrate(&model.VulnerabilityModel{}); err != nil {
			return nil, fmt.Errorf("unable to migrate Vulnerability model: %w", err)
		}
		if err := db.AutoMigrate(&model.VulnerabilityMetadataModel{}); err != nil {
			return nil, fmt.Errorf("unable to migrate Vulnerability Metadata model: %w", err)
		}
	}

	return &store{
		db: db,
	}, nil
}

// GetID fetches the metadata about the databases schema version and build time.
func (s *store) GetID() (*v2.ID, error) {
	var models []model.IDModel
	result := s.db.Find(&models)
	if result.Error != nil {
		return nil, result.Error
	}

	switch {
	case len(models) > 1:
		return nil, fmt.Errorf("found multiple DB IDs")
	case len(models) == 1:
		id, err := models[0].Inflate()
		if err != nil {
			return nil, err
		}
		return &id, nil
	}

	return nil, nil
}

// SetID stores the databases schema version and build time.
func (s *store) SetID(id v2.ID) error {
	var ids []model.IDModel

	// replace the existing ID with the given one
	s.db.Find(&ids).Delete(&ids)

	m := model.NewIDModel(id)
	result := s.db.Create(&m)

	if result.RowsAffected != 1 {
		return fmt.Errorf("unable to add id (%d rows affected)", result.RowsAffected)
	}

	return result.Error
}

// GetVulnerability retrieves one or more vulnerabilities given a namespace and package name.
func (s *store) GetVulnerability(namespace, packageName string) ([]v2.Vulnerability, error) {
	var models []model.VulnerabilityModel

	result := s.db.Where("namespace = ? AND package_name = ?", namespace, packageName).Find(&models)

	var vulnerabilities = make([]v2.Vulnerability, len(models))
	for idx, m := range models {
		vulnerability, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		vulnerabilities[idx] = vulnerability
	}

	return vulnerabilities, result.Error
}

// AddVulnerability saves one or more vulnerabilities into the sqlite3 store.
func (s *store) AddVulnerability(vulnerabilities ...v2.Vulnerability) error {
	for _, vulnerability := range vulnerabilities {
		m := model.NewVulnerabilityModel(vulnerability)

		result := s.db.Create(&m)
		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return fmt.Errorf("unable to add vulnerability (%d rows affected)", result.RowsAffected)
		}
	}
	return nil
}

// GetVulnerabilityMetadata retrieves metadata for the given vulnerability ID relative to a specific record source.
func (s *store) GetVulnerabilityMetadata(id, recordSource string) (*v2.VulnerabilityMetadata, error) {
	var models []model.VulnerabilityMetadataModel

	result := s.db.Where(&model.VulnerabilityMetadataModel{ID: id, RecordSource: recordSource}).Find(&models)
	if result.Error != nil {
		return nil, result.Error
	}

	switch {
	case len(models) > 1:
		return nil, fmt.Errorf("found multiple metadatas for single ID=%q RecordSource=%q", id, recordSource)
	case len(models) == 1:
		metadata, err := models[0].Inflate()
		if err != nil {
			return nil, err
		}

		return &metadata, nil
	}

	return nil, nil
}

// AddVulnerabilityMetadata stores one or more vulnerability metadata models into the sqlite DB.
func (s *store) AddVulnerabilityMetadata(metadata ...v2.VulnerabilityMetadata) error {
	for _, m := range metadata {
		existing, err := s.GetVulnerabilityMetadata(m.ID, m.RecordSource)
		if err != nil {
			return fmt.Errorf("failed to verify existing entry: %w", err)
		}

		if existing != nil {
			// merge with the existing entry

			cvssV3Diffs := deep.Equal(existing.CvssV3, m.CvssV3)
			cvssV2Diffs := deep.Equal(existing.CvssV2, m.CvssV2)

			switch {
			case existing.Severity != m.Severity:
				return fmt.Errorf("existing metadata has mismatched severity (%q!=%q)", existing.Severity, m.Severity)
			case existing.Description != m.Description:
				return fmt.Errorf("existing metadata has mismatched description (%q!=%q)", existing.Description, m.Description)
			case existing.CvssV2 != nil && len(cvssV2Diffs) > 0:
				return fmt.Errorf("existing metadata has mismatched cvss-v2: %+v", cvssV2Diffs)
			case existing.CvssV3 != nil && len(cvssV3Diffs) > 0:
				return fmt.Errorf("existing metadata has mismatched cvss-v3: %+v", cvssV3Diffs)
			default:
				existing.CvssV2 = m.CvssV2
				existing.CvssV3 = m.CvssV3
			}

			links := internal.NewStringSetFromSlice(existing.Links)
			for _, l := range m.Links {
				links.Add(l)
			}

			existing.Links = links.ToSlice()
			sort.Strings(existing.Links)

			newModel := model.NewVulnerabilityMetadataModel(*existing)
			result := s.db.Save(&newModel)

			if result.RowsAffected != 1 {
				return fmt.Errorf("unable to merge vulnerability metadata (%d rows affected)", result.RowsAffected)
			}

			if result.Error != nil {
				return result.Error
			}
		} else {
			// this is a new entry
			newModel := model.NewVulnerabilityMetadataModel(m)
			result := s.db.Create(&newModel)
			if result.Error != nil {
				return result.Error
			}

			if result.RowsAffected != 1 {
				return fmt.Errorf("unable to add vulnerability metadata (%d rows affected)", result.RowsAffected)
			}
		}
	}
	return nil
}
