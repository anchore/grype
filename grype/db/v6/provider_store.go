package v6

import (
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type ProviderStoreWriter interface {
	AddProvider(p *Provider) error
}

type ProviderStoreReader interface {
	GetProvider(name string) (*Provider, error)
	AllProviders() ([]Provider, error)
}

type providerStore struct {
	db *gorm.DB
}

func newProviderStore(db *gorm.DB) *providerStore {
	return &providerStore{
		db: db,
	}
}

func (s *providerStore) AddProvider(p *Provider) error {
	log.WithFields("name", p.ID).Trace("writing provider record")

	var existingProvider Provider
	result := s.db.Where("id = ? AND version = ?", p.ID, p.Version).First(&existingProvider)
	if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to find provider (name=%q version=%q): %w", p.ID, p.Version, result.Error)
	}

	if result.Error == nil {
		// overwrite the existing provider if found
		existingProvider.Processor = p.Processor
		existingProvider.DateCaptured = p.DateCaptured
		existingProvider.InputDigest = p.InputDigest
	} else {
		// create a new provider record if not found
		existingProvider = *p
	}

	if err := s.db.Save(&existingProvider).Error; err != nil {
		return fmt.Errorf("failed to save provider (name=%q version=%q): %w", p.ID, p.Version, err)
	}

	return nil
}

func (s *providerStore) GetProvider(name string) (*Provider, error) {
	log.WithFields("name", name).Trace("fetching provider record")

	var provider Provider
	result := s.db.Where("id = ?", name).First(&provider)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to fetch provider (name=%q): %w", name, result.Error)
	}

	return &provider, nil
}

func (s *providerStore) AllProviders() ([]Provider, error) {
	log.Trace("fetching all provider records")

	var providers []Provider
	result := s.db.Find(&providers)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to fetch all providers: %w", result.Error)
	}

	sort.Slice(providers, func(i, j int) bool {
		return providers[i].ID < providers[j].ID
	})

	return providers, nil
}
