package v6

import (
	"github.com/anchore/grype/internal/log"
)

type OperatingSystemStore interface {
	GetOperatingSystem(name, majorVersion string, minorVersion *string) ([]OperatingSystem, error)
	GetOperatingSystemByName(name string) (*OperatingSystem, error)
	GetOperatingSystemByCodename(codename string) (*OperatingSystem, error)
}

type operatingSystemStore struct {
	*StoreConfig
	*state
}

func NewOperatingSystemStore(cfg *StoreConfig) OperatingSystemStore {
	return &operatingSystemStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

func (o operatingSystemStore) GetOperatingSystem(name, majorVersion string, minorVersion *string) ([]OperatingSystem, error) {
	log.WithFields("name", name, "major-version", majorVersion, "minor-version", minorVersion).Trace("fetching OperatingSystem record")

	var operatingSystems []OperatingSystem
	query := o.db.Where("name = ? AND major_version = ?", name, majorVersion)
	if minorVersion != nil {
		query = query.Where("minor_version = ?", *minorVersion)
	}
	result := query.Find(&operatingSystems)
	return operatingSystems, result.Error
}

func (o operatingSystemStore) GetOperatingSystemByName(name string) (*OperatingSystem, error) {
	log.WithFields("name", name).Trace("fetching OperatingSystem record")

	var operatingSystem OperatingSystem
	result := o.db.Where("name = ?", name).First(&operatingSystem)
	if result.Error != nil {
		return nil, result.Error
	}
	return &operatingSystem, nil
}

func (o operatingSystemStore) GetOperatingSystemByCodename(codename string) (*OperatingSystem, error) {
	log.WithFields("codename", codename).Trace("fetching OperatingSystem record")

	var operatingSystem OperatingSystem
	result := o.db.Where("codename = ?", codename).First(&operatingSystem)
	if result.Error != nil {
		return nil, result.Error
	}
	return &operatingSystem, nil
}
