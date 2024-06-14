package v6

type AffectedStore interface {
	// TODO: getters
}

type affectedStore struct {
	*StoreConfig
	*state
}

func NewAffectedStore(cfg *StoreConfig) AffectedStore {
	return &affectedStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}
