package store

import (
	v3 "github.com/anchore/grype/grype/db/v3"
	"github.com/anchore/grype/grype/db/v3/store/model"
)

type storeKey struct {
	id          string
	namespace   string
	packageName string
	version     string
	cpes        string
}

type storeItem[T any] struct {
	item *T
	seen bool
}

func (s *store) GetAllSerializedVulnerabilities() (v3.SerializedVulnerabilities, error) {
	return getAllRowsFromTable[model.VulnerabilityModel](s)
}

func (s *store) GetAllSerializedVulnerabilityMetadata() (v3.SerializedVulnerabilityMetadata, error) {
	return getAllRowsFromTable[model.VulnerabilityMetadataModel](s)
}

func getAllRowsFromTable[T model.VulnerabilityModel | model.VulnerabilityMetadataModel](s *store) (*[]T, error) {
	var models []T
	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}
	return &models, nil
}

func diffDatabaseTable[T model.VulnerabilityModel | model.VulnerabilityMetadataModel](s *store, targetModels *[]T) (*[]v3.Diff, error) {
	var models []T
	diffs := []v3.Diff{}

	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}

	m := make(map[storeKey]*storeItem[T], len(models))
	for idx, model := range models {
		m[getKey(model)] = &storeItem[T]{
			item: &models[idx],
			seen: false,
		}
	}

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getKey(targetModel)
		if baseModel, exists := m[k]; exists {
			baseModel.seen = true

			clearPK(&targetModel)
			clearPK(baseModel.item)

			if *baseModel.item != targetModel {
				diffs = append(diffs, v3.Diff{
					Reason:    v3.DiffChanged,
					ID:        k.id,
					Namespace: k.namespace,
				})
			}
		} else {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffAdded,
				ID:        k.id,
				Namespace: k.namespace,
			})
		}
	}
	for k, model := range m {
		if !model.seen {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffRemoved,
				ID:        k.id,
				Namespace: k.namespace,
			})
		}
	}

	return &diffs, nil
}

func clearPK(item interface{}) {
	// nolint:gocritic
	switch i := item.(type) {
	case *model.VulnerabilityModel:
		i.PK = 0
	}
}

func getKey(item interface{}) storeKey {
	switch i := item.(type) {
	case model.VulnerabilityModel:
		return storeKey{i.ID, i.Namespace, i.PackageName, i.VersionConstraint, i.CPEs}
	case model.VulnerabilityMetadataModel:
		return storeKey{i.ID, i.Namespace, "", "", ""}
	}
	return storeKey{}
}
