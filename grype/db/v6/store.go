package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
	"io"
	"path/filepath"
)

// note: this is coupled to historical distribution -- this value cannot change
const vulnerabilityStoreFileName = "vulnerability.db"

type StoreConfig struct {
	BatchSize int
	DBDirPath string
	Overwrite bool

	current *state
}

type Store interface {
	AffectedStore
	VulnerabilityStore
	AffectedPackageStore
	ProviderStore
	OperatingSystemStore
	io.Closer
}

// Store holds an instance of the database connection
type store struct {
	cfg *StoreConfig

	AffectedStore
	VulnerabilityStore
	AffectedPackageStore
	ProviderStore
	OperatingSystemStore
}

func (c *StoreConfig) state() *state {
	if c.current == nil {
		var err error
		c.current, err = newState(c.DBFilePath(), c.Overwrite)
		if err != nil {
			// TODO:...
			panic(err)
		}
	}
	return c.current
}

func (c *StoreConfig) DBFilePath() string {
	return filepath.Join(c.DBDirPath, vulnerabilityStoreFileName)
}

// New creates a new instance of the Store.
func New(cfg StoreConfig) (Store, error) {
	return &store{
		cfg:                  &cfg,
		ProviderStore:        NewProviderStore(&cfg),
		OperatingSystemStore: NewOperatingSystemStore(&cfg),
		AffectedStore:        NewAffectedStore(&cfg),
		VulnerabilityStore:   NewVulnerabilityStore(&cfg),
		AffectedPackageStore: NewAffectedPackageStore(&cfg),
	}, nil
}

func (s store) Close() error {
	log.Debug("closing store")
	st := s.cfg.state()
	return st.db.Exec(fmt.Sprintf("VACUUM main into %q", st.destination)).Error
}
