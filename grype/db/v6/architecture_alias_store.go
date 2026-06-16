package v6

import (
	"fmt"

	"gorm.io/gorm"
)

type ArchitectureAliasStoreReader interface {
	// GetArchitectureAliases returns the architecture alias table (alias spelling -> canonical
	// token), used by the architecture qualifier to fold dialect spellings at match time.
	GetArchitectureAliases() (map[string]string, error)
}

type architectureAliasStore struct {
	db *gorm.DB
}

func newArchitectureAliasStore(db *gorm.DB) *architectureAliasStore {
	return &architectureAliasStore{db: db}
}

// GetArchitectureAliases returns the architecture alias table as a map of alias spelling to
// canonical token. A database built before this table existed has no such table; that is not
// an error — an empty map is returned, which the architecture qualifier reads as "fall back to
// the built-in default aliases".
func (s *architectureAliasStore) GetArchitectureAliases() (map[string]string, error) {
	if !s.db.Migrator().HasTable(&ArchitectureAlias{}) {
		return map[string]string{}, nil
	}

	var rows []ArchitectureAlias
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("unable to read architecture aliases: %w", err)
	}

	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Alias] = r.Canonical
	}
	return out, nil
}
