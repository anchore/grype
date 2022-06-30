package store

import (
	"strings"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	v3 "github.com/anchore/grype/grype/db/v3"
	"github.com/anchore/grype/grype/db/v3/store/model"
	diffEvents "github.com/anchore/grype/grype/differ/events"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
)

type storeKey struct {
	id          string
	namespace   string
	packageName string
}

type storeVulnerability struct {
	items []*v3.Vulnerability
	seen  bool
}
type storeMetadata struct {
	item *v3.VulnerabilityMetadata
	seen bool
}

func trackDiff() (*progress.Manual, *progress.Manual) {
	rowsProcessed := progress.Manual{}
	differencesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.DatabaseDiffingStarted,
		Value: diffEvents.Monitor{
			RowsProcessed:         progress.Monitorable(&rowsProcessed),
			DifferencesDiscovered: progress.Monitorable(&differencesDiscovered),
		},
	})
	return &rowsProcessed, &differencesDiscovered
}

func diffVulnerabilities(s *store, targetModels *[]v3.Vulnerability, queryProgress *progress.Manual, differentItems *progress.Manual) (*[]v3.Diff, error) {
	var models []model.VulnerabilityModel
	diffs := []v3.Diff{}

	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}
	queryProgress.N++

	m := make(map[storeKey]*storeVulnerability, len(models))
	for _, model := range models {
		inflatedModel, err := model.Inflate()
		if err != nil {
			return nil, err
		}

		if storeVuln, exists := m[getVulnerabilityKey(inflatedModel)]; exists {
			storeVuln.items = append(storeVuln.items, &inflatedModel)
		} else {
			m[getVulnerabilityKey(inflatedModel)] = &storeVulnerability{
				items: []*v3.Vulnerability{&inflatedModel},
				seen:  false,
			}
		}
	}

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getVulnerabilityKey(targetModel)
		if baseModel, exists := m[k]; exists {
			baseModel.seen = true
			matched := false
			for _, item := range baseModel.items {
				if item.Equal(targetModel) {
					matched = true
				}
			}
			if !matched {
				diffs = append(diffs, v3.Diff{
					Reason:    v3.DiffChanged,
					ID:        k.id,
					Namespace: k.namespace,
				})
				differentItems.N++
			}
		} else {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffAdded,
				ID:        k.id,
				Namespace: k.namespace,
			})
			differentItems.N++
		}
	}
	for k, model := range m {
		if !model.seen {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffRemoved,
				ID:        k.id,
				Namespace: k.namespace,
			})
			differentItems.N++
		}
	}

	return &diffs, nil
}

func getVulnerabilityKey(vuln v3.Vulnerability) storeKey {
	var sb strings.Builder
	for _, str := range vuln.CPEs {
		sb.WriteString(str)
	}
	return storeKey{vuln.ID, vuln.Namespace, vuln.PackageName}
}

func diffVulnerabilityMetadata(s *store, targetModels *[]v3.VulnerabilityMetadata, queryProgress *progress.Manual, differentItems *progress.Manual) (*[]v3.Diff, error) {
	var models []model.VulnerabilityMetadataModel
	diffs := []v3.Diff{}

	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}
	queryProgress.N++

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
				baseModel.item.Equal(targetModel)
				diffs = append(diffs, v3.Diff{
					Reason:    v3.DiffChanged,
					ID:        k.id,
					Namespace: k.namespace,
				})
				differentItems.N++
			}
		} else {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffAdded,
				ID:        k.id,
				Namespace: k.namespace,
			})
			differentItems.N++
		}
	}
	for k, model := range m {
		if !model.seen {
			diffs = append(diffs, v3.Diff{
				Reason:    v3.DiffRemoved,
				ID:        k.id,
				Namespace: k.namespace,
			})
			differentItems.N++
		}
	}

	return &diffs, nil
}

func getMetadataKey(metadata v3.VulnerabilityMetadata) storeKey {
	return storeKey{metadata.ID, metadata.Namespace, ""}
}
