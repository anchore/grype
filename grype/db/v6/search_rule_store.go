package v6

import (
	"fmt"
	"slices"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type SearchRuleStoreReader interface {
	// GetSearchRules returns the search rules this client can use, or nil when the DB predates the table
	GetSearchRules() ([]SearchRule, error)
}

type SearchRuleStoreWriter interface {
	// AddSearchRules writes rules beyond the built-in ones the DB is created with (see InitialData)
	AddSearchRules(rules ...*SearchRule) error
}

type searchRuleStore struct {
	db *gorm.DB
}

func newSearchRuleStore(db *gorm.DB) *searchRuleStore {
	return &searchRuleStore{db: db}
}

func (s *searchRuleStore) GetSearchRules() ([]SearchRule, error) {
	if !s.db.Migrator().HasTable(&SearchRule{}) {
		return nil, nil
	}

	var rows []SearchRule
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("unable to read search rules: %w", err)
	}

	// skip rows this client cannot use (e.g. no action, or one a newer DB introduced that fails to validate on this grype version)
	rows = slices.DeleteFunc(rows, func(row SearchRule) bool {
		if err := row.Validate(); err != nil {
			log.WithFields("error", err, "row", row).Debug("skipping invalid search rule")
			return true
		}
		return false
	})

	return rows, nil
}

func (s *searchRuleStore) AddSearchRules(rules ...*SearchRule) error {
	if len(rules) == 0 {
		return nil
	}
	if err := s.db.Create(rules).Error; err != nil {
		return fmt.Errorf("unable to create search rules: %w", err)
	}
	return nil
}
