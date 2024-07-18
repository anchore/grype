package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
	"io"
)

// note: this is coupled to historical distribution -- this value cannot change
const vulnerabilityStoreFileName = "vulnerability.db"

type Store interface {
	AffectedPackageStore
	AffectedCPEStore
	VulnerabilityStore
	io.Closer
}

// Store holds an instance of the database connection
type store struct {
	*affectedPackageStore
	*vulnerabilityStore
	*affectedCPEStore
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
	}, nil
}

func (s store) Close() error {
	log.Debug("closing store")
	// TODO: this is NOT what we want to do on read only things.... just on writes
	st := s.cfg.state()
	return st.db.Exec(fmt.Sprintf("VACUUM main into %q", st.destination)).Error
}
