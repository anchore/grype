package v6

import (
	"slices"

	"gorm.io/gorm"
)

type idRef[T any] struct {
	id  *ID
	ref **T
}

type refProvider[T, R any] func(*T) idRef[R]

type idProvider[T any] func(*T) ID

func fillRefs[T, R any](db *gorm.DB, handles []T, getRef refProvider[T, R], refID idProvider[R]) error {
	if len(handles) == 0 {
		return nil
	}

	// collect all ref locations and IDs
	var refs []idRef[R]
	var ids []ID
	for i := range handles {
		h := &handles[i]
		ref := getRef(h)
		if ref.id == nil {
			continue
		}
		refs = append(refs, ref)
		id := *ref.id
		if slices.Contains(ids, id) {
			continue
		}
		ids = append(ids, id)
	}

	// load a map with all id -> ref results
	var values []R
	tx := db.Where("id IN (?)", ids)
	LogQuery(tx, &values)
	err := tx.Find(&values).Error
	if err != nil {
		return err
	}
	refsByID := map[ID]*R{}
	for i := range values {
		v := &values[i]
		id := refID(v)
		refsByID[id] = v
	}

	// assign matching refs back to the object graph
	for _, ref := range refs {
		if ref.id == nil {
			continue
		}
		incomingRef := refsByID[*ref.id]
		*ref.ref = incomingRef
	}

	return nil
}

// func collectUniqueValues[From any, To comparable](values []From, mapFn func(From) To) []To {
//	var out []To
//	for i := range values {
//		v := mapFn(values[i])
//		if slices.Contains(out, v) {
//			continue
//		}
//		out = append(out, v)
//	}
//	return out
//}

// func mapResults[T any](db *gorm.DB, ids []v6.ID, refID idProvider[T]) (map[v6.ID]T, error) {
//	var results []T
//	// FIXME probably need to build IN clause
//	err := db.Where("ID IN (?)", ids).Find(&results).Error
//	out := map[v6.ID]T{}
//	for _, result := range results {
//		out[refID(result)] = result
//	}
//	return out, err
//}
