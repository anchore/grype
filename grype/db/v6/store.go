package v6

import (
	"io"
)

// note: this is coupled to historical distribution -- this value cannot change
const vulnerabilityStoreFileName = "vulnerability.db"

type Store interface {
	AffectedPackageStore
	AffectedCPEStore
	VulnerabilityStore
	ProviderStore
	io.Closer
}

// Store holds an instance of the database connection
type store struct {
	*affectedPackageStore
	*vulnerabilityStore
	*affectedCPEStore
	*providerStore
	cfg *StoreConfig
}

// New creates a new instance of the Store.
func New(cfg StoreConfig) (Store, error) {
	bs := newBlobStore(&cfg)
	return &store{
		cfg:                  &cfg,
		affectedPackageStore: newAffectedPackageStore(&cfg, bs),
		affectedCPEStore:     newAffectedCPEStore(&cfg, bs),
		vulnerabilityStore:   newVulnerabilityStore(&cfg, bs),
		providerStore:        newProviderStore(&cfg),
	}, nil
}

func (s store) Close() error {
	return s.cfg.state().close()
}
