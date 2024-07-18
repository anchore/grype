package v6

import "path/filepath"

type StoreConfig struct {
	BatchSize int
	DBDirPath string
	Overwrite bool

	current *state
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
