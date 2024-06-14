package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
)

type ProviderStore interface {
	AddProviders(providers ...*Provider) error
	GetProviders() ([]Provider, error)
	GetProviderByName(name string) (*Provider, error)
}

type providerStore struct {
	*StoreConfig
	*state
}

func NewProviderStore(cfg *StoreConfig) ProviderStore {
	return &providerStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

func (s *providerStore) AddProviders(providers ...*Provider) error {
	for i, provider := range providers {
		log.WithFields("name", provider.ID).Trace("adding Provider record")

		var existingProvider Provider
		result := s.db.Where("name = ? AND version = ?", provider.ID, provider.Version).FirstOrCreate(&existingProvider, provider)
		if result.Error != nil {
			return fmt.Errorf("failed to create provider (name=%q version=%q): %w", provider.ID, provider.Version, result.Error)
		}
		providers[i] = &existingProvider
	}
	return nil
}
func (p providerStore) GetProviders() ([]Provider, error) {
	log.Trace("fetching Provider records")

	var models []Provider

	result := p.db.Find(&models)
	return models, result.Error
}

func (p providerStore) GetProviderByName(name string) (*Provider, error) {
	log.WithFields("name", name).Trace("fetching Provider record")

	var model *Provider

	result := p.db.Where("name = ?", name).First(&model)
	return model, result.Error
}
