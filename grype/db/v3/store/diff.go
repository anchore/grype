package store

import (
	"strings"

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

type storeVulnerability struct {
	item *v3.Vulnerability
	seen bool
}
type storeMetadata struct {
	item *v3.VulnerabilityMetadata
	seen bool
}

//nolint:dupl
func diffVulnerabilities(s *store, targetModels *[]v3.Vulnerability) (*[]v3.Diff, error) {
	var models []model.VulnerabilityModel
	diffs := []v3.Diff{}

	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}

	m := make(map[storeKey]*storeVulnerability, len(models))
	for _, model := range models {
		inflatedModel, err := model.Inflate()
		if err != nil {
			return nil, err
		}
		m[getVulnerabilityKey(inflatedModel)] = &storeVulnerability{
			item: &inflatedModel,
			seen: false,
		}
	}

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getVulnerabilityKey(targetModel)
		if baseModel, exists := m[k]; exists {
			baseModel.seen = true

			if !baseModel.item.Equal(targetModel) {
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

func getVulnerabilityKey(vuln v3.Vulnerability) storeKey {
	var sb strings.Builder
	for _, str := range vuln.CPEs {
		sb.WriteString(str)
	}
	return storeKey{vuln.ID, vuln.Namespace, vuln.PackageName, vuln.VersionConstraint, sb.String()}
}

//nolint:dupl
func diffVulnerabilityMetadata(s *store, targetModels *[]v3.VulnerabilityMetadata) (*[]v3.Diff, error) {
	var models []model.VulnerabilityMetadataModel
	diffs := []v3.Diff{}

	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}

	m := make(map[storeKey]*storeMetadata, len(models))
	for _, model := range models {
		inflatedModel, err := model.Inflate()
		if err != nil {
			return nil, err
		}
		m[getMetadataKey(inflatedModel)] = &storeMetadata{
			item: &inflatedModel,
			seen: false,
		}
	}

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getMetadataKey(targetModel)
		if baseModel, exists := m[k]; exists {
			baseModel.seen = true

			if !baseModel.item.Equal(targetModel) {
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

func getMetadataKey(metadata v3.VulnerabilityMetadata) storeKey {
	return storeKey{metadata.ID, metadata.Namespace, "", "", ""}
}
