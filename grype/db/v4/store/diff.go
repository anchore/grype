package store

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	v4 "github.com/anchore/grype/grype/db/v4"
	diffEvents "github.com/anchore/grype/grype/differ/events"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
)

type storeKey struct {
	id          string
	namespace   string
	packageName string
}

type PkgMap = map[storeKey][]string

type storeVulnerabilityList struct {
	items map[storeKey][]storeVulnerability
	seen  bool
}
type storeVulnerability struct {
	item *v4.Vulnerability
	seen bool
}
type storeMetadata struct {
	item *v4.VulnerabilityMetadata
	seen bool
}

// create manual progress bars for tracking the database diff's progress
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

// creates a map from an unpackaged key to a list of all packages associated with it
func buildVulnerabilityPkgsMap(models *[]v4.Vulnerability) *map[storeKey][]string {
	storeMap := make(map[storeKey][]string)
	for _, m := range *models {
		model := m
		k := getVulnerabilityParentKey(model)
		if storeVuln, exists := storeMap[k]; exists {
			storeMap[k] = append(storeVuln, model.PackageName)
		} else {
			storeMap[k] = []string{model.PackageName}
		}
	}
	return &storeMap
}

// creates a diff from the given key using the package maps information to populate
// the relevant packages affected by the update
func createDiff(baseStore, targetStore *PkgMap, key storeKey, reason v4.DiffReason) *v4.Diff {
	pkgMap := make(map[string]struct{})

	key.packageName = ""
	if baseStore != nil {
		if basePkgs, exists := (*baseStore)[key]; exists {
			for _, pkg := range basePkgs {
				pkgMap[pkg] = struct{}{}
			}
		}
	}
	if targetStore != nil {
		if targetPkgs, exists := (*targetStore)[key]; exists {
			for _, pkg := range targetPkgs {
				pkgMap[pkg] = struct{}{}
			}
		}
	}
	pkgs := []string{}
	for pkg := range pkgMap {
		pkgs = append(pkgs, pkg)
	}

	return &v4.Diff{
		Reason:    reason,
		ID:        key.id,
		Namespace: key.namespace,
		Packages:  pkgs,
	}
}

// gets an unpackaged key from a vulnerability
func getVulnerabilityParentKey(vuln v4.Vulnerability) storeKey {
	return storeKey{vuln.ID, vuln.Namespace, ""}
}

// gets a packaged key from a vulnerability
func getVulnerabilityKey(vuln v4.Vulnerability) storeKey {
	return storeKey{vuln.ID, vuln.Namespace, vuln.PackageName}
}

type VulnerabilitySet struct {
	data map[storeKey]*storeVulnerabilityList
}

func NewVulnerabilitySet(models *[]v4.Vulnerability) *VulnerabilitySet {
	m := make(map[storeKey]*storeVulnerabilityList, len(*models))
	for _, mm := range *models {
		model := mm
		parentKey := getVulnerabilityParentKey(model)
		vulnKey := getVulnerabilityKey(model)
		if storeVuln, exists := m[parentKey]; exists {
			if kk, exists := storeVuln.items[vulnKey]; exists {
				storeVuln.items[vulnKey] = append(kk, storeVulnerability{
					item: &model,
					seen: false,
				})
			} else {
				storeVuln.items[vulnKey] = []storeVulnerability{{&model, false}}
			}
		} else {
			vuln := storeVulnerabilityList{
				items: make(map[storeKey][]storeVulnerability),
				seen:  false,
			}
			vuln.items[vulnKey] = []storeVulnerability{{&model, false}}
			m[parentKey] = &vuln
		}
	}
	return &VulnerabilitySet{
		data: m,
	}
}

func (v *VulnerabilitySet) in(item v4.Vulnerability) bool {
	_, exists := v.data[getVulnerabilityParentKey(item)]
	return exists
}

func (v *VulnerabilitySet) match(item v4.Vulnerability) bool {
	if parent, exists := v.data[getVulnerabilityParentKey(item)]; exists {
		parent.seen = true
		key := getVulnerabilityKey(item)
		if children, exists := parent.items[key]; exists {
			for idx, child := range children {
				if item.Equal(*child.item) {
					children[idx].seen = true
					return true
				}
			}
		}
	}
	return false
}

func (v *VulnerabilitySet) getUnmatched() ([]storeKey, []storeKey) {
	notSeen := []storeKey{}
	notEntirelySeen := []storeKey{}
	for k, item := range v.data {
		if !item.seen {
			notSeen = append(notSeen, k)
			continue
		}
	componentLoop:
		for _, components := range item.items {
			for _, component := range components {
				if !component.seen {
					notEntirelySeen = append(notEntirelySeen, k)
					break componentLoop
				}
			}
		}
	}
	return notSeen, notEntirelySeen
}

func diffVulnerabilities(baseModels, targetModels *[]v4.Vulnerability, basePkgsMap, targetPkgsMap *PkgMap, differentItems *progress.Manual) *map[string]*v4.Diff {
	diffs := make(map[string]*v4.Diff)
	m := NewVulnerabilitySet(baseModels)

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getVulnerabilityKey(targetModel)
		if m.in(targetModel) {
			matched := m.match(targetModel)
			if !matched {
				if _, exists := diffs[k.id+k.namespace]; exists {
					continue
				}
				diffs[k.id+k.namespace] = createDiff(basePkgsMap, targetPkgsMap, k, v4.DiffChanged)
				differentItems.Increment()
			}
		} else {
			if _, exists := diffs[k.id+k.namespace]; exists {
				continue
			}
			diffs[k.id+k.namespace] = createDiff(nil, targetPkgsMap, k, v4.DiffAdded)
			differentItems.Increment()
		}
	}
	notSeen, partialSeen := m.getUnmatched()
	for _, k := range partialSeen {
		if _, exists := diffs[k.id+k.namespace]; exists {
			continue
		}
		diffs[k.id+k.namespace] = createDiff(basePkgsMap, targetPkgsMap, k, v4.DiffChanged)
		differentItems.Increment()
	}
	for _, k := range notSeen {
		if _, exists := diffs[k.id+k.namespace]; exists {
			continue
		}
		diffs[k.id+k.namespace] = createDiff(basePkgsMap, nil, k, v4.DiffRemoved)
		differentItems.Increment()
	}

	return &diffs
}

type MetadataSet struct {
	data map[storeKey]*storeMetadata
}

func NewMetadataSet(models *[]v4.VulnerabilityMetadata) *MetadataSet {
	m := make(map[storeKey]*storeMetadata, len(*models))
	for _, mm := range *models {
		model := mm
		m[getMetadataKey(model)] = &storeMetadata{
			item: &model,
			seen: false,
		}
	}
	return &MetadataSet{
		data: m,
	}
}

func (v *MetadataSet) in(item v4.VulnerabilityMetadata) bool {
	_, exists := v.data[getMetadataKey(item)]
	return exists
}

func (v *MetadataSet) match(item v4.VulnerabilityMetadata) bool {
	if baseModel, exists := v.data[getMetadataKey(item)]; exists {
		baseModel.seen = true
		return baseModel.item.Equal(item)
	}
	return false
}

func (v *MetadataSet) getUnmatched() []storeKey {
	notSeen := []storeKey{}
	for k, item := range v.data {
		if !item.seen {
			notSeen = append(notSeen, k)
		}
	}
	return notSeen
}

func diffVulnerabilityMetadata(baseModels, targetModels *[]v4.VulnerabilityMetadata, basePkgsMap, targetPkgsMap *PkgMap, differentItems *progress.Manual) *map[string]*v4.Diff {
	diffs := make(map[string]*v4.Diff)
	m := NewMetadataSet(baseModels)

	for _, tModel := range *targetModels {
		targetModel := tModel
		k := getMetadataKey(targetModel)
		if m.in(targetModel) {
			if !m.match(targetModel) {
				if _, exists := diffs[k.id+k.namespace]; exists {
					continue
				}
				diffs[k.id+k.namespace] = createDiff(basePkgsMap, targetPkgsMap, k, v4.DiffChanged)
				differentItems.Increment()
			}
		} else {
			if _, exists := diffs[k.id+k.namespace]; exists {
				continue
			}
			diffs[k.id+k.namespace] = createDiff(nil, targetPkgsMap, k, v4.DiffAdded)
			differentItems.Increment()
		}
	}
	for _, k := range m.getUnmatched() {
		if _, exists := diffs[k.id+k.namespace]; exists {
			continue
		}
		diffs[k.id+k.namespace] = createDiff(basePkgsMap, nil, k, v4.DiffRemoved)
		differentItems.Increment()
	}

	return &diffs
}

func getMetadataKey(metadata v4.VulnerabilityMetadata) storeKey {
	return storeKey{metadata.ID, metadata.Namespace, ""}
}
