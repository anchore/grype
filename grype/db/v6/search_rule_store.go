package v6

import (
	"fmt"

	"gorm.io/gorm"
)

type SearchRuleStoreReader interface {
	// GetSearchRules returns the search rules (distro/package predicates -> additional search
	// names and/or a different OS channel or name), used at match time to rewrite the specifiers
	// an individual package's vulnerability lookup is performed with.
	GetSearchRules() ([]SearchRule, error)
}

type searchRuleStore struct {
	db *gorm.DB
}

func newSearchRuleStore(db *gorm.DB) *searchRuleStore {
	return &searchRuleStore{db: db}
}

// GetSearchRules returns all search rules. Which rules apply to a search is decided by their
// priority, so the order rows come back in carries no meaning and none is imposed. A database
// built before this table existed has no such table; that is not an error — nil is returned,
// which the caller reads as "fall back to the built-in defaults".
func (s *searchRuleStore) GetSearchRules() ([]SearchRule, error) {
	if !s.db.Migrator().HasTable(&SearchRule{}) {
		return nil, nil
	}

	var rows []SearchRule
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("unable to read search rules: %w", err)
	}

	return rows, nil
}
