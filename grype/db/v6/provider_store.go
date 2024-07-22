package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
)

type ProviderStore interface {
	AddProvider(p *Provider) error
	// TODO add getters
}

type providerStore struct {
	*StoreConfig
	*state
}

func newProviderStore(cfg *StoreConfig) *providerStore {
	return &providerStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

func (s *providerStore) AddProvider(p *Provider) error {
	log.WithFields("name", p.ID).Trace("adding provider record")

	var existingProvider Provider
	result := s.db.Where("id = ? AND version = ?", p.ID, p.Version).FirstOrCreate(&existingProvider, p)
	if result.Error != nil {
		return fmt.Errorf("failed to create provider (name=%q version=%q): %w", p.ID, p.Version, result.Error)
	}

	return nil
}
