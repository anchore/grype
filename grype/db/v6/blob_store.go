package v6

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type blobable interface {
	getBlobID() ID
	getBlobValue() any
	setBlobID(ID)
	setBlob([]byte) error
}

type blobStore struct {
	db          *gorm.DB
	idsByDigest map[string]ID
}

func newBlobStore(db *gorm.DB) *blobStore {
	return &blobStore{
		db:          db,
		idsByDigest: make(map[string]ID),
	}
}

func (s *blobStore) addBlobable(bs ...blobable) error {
	for i := range bs {
		b := bs[i]
		v := b.getBlobValue()
		if v == nil {
			continue
		}
		bl := newBlob(v)

		if err := s.addBlobs(bl); err != nil {
			return err
		}

		b.setBlobID(bl.ID)
	}
	return nil
}

func (s *blobStore) addBlobs(blobs ...*Blob) error {
	for i := range blobs {
		v := blobs[i]
		digest := v.computeDigest()

		if id, ok := s.idsByDigest[digest]; ok && id != 0 {
			v.ID = id
			continue
		}

		if err := s.db.Create(v).Error; err != nil {
			return fmt.Errorf("failed to create blob: %w", err)
		}

		if v.ID != 0 {
			s.idsByDigest[digest] = v.ID
		}
	}
	return nil
}

func (s *blobStore) getBlobValues(ids ...ID) ([]Blob, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var blobs []Blob
	if err := s.db.Where("id IN ?", ids).Find(&blobs).Error; err != nil {
		return nil, fmt.Errorf("failed to get blob values: %w", err)
	}
	return blobs, nil
}

func (s *blobStore) attachBlobValue(bs ...blobable) error {
	start := time.Now()
	defer func() {
		log.WithFields("duration", time.Since(start), "count", len(bs)).Trace("attached blob values")
	}()
	var ids []ID
	var setterByID = make(map[ID][]blobable)
	for i := range bs {
		b := bs[i]

		id := b.getBlobID()

		// skip fetching this blob if there is no blobID, or if we already have this blob
		if id == 0 || b.getBlobValue() != nil {
			continue
		}

		ids = append(ids, id)
		setterByID[id] = append(setterByID[id], b)
	}

	vs, err := s.getBlobValues(ids...)
	if err != nil {
		return fmt.Errorf("failed to get blob value: %w", err)
	}

	for _, b := range vs {
		if b.Value == "" {
			continue
		}
		for _, setter := range setterByID[b.ID] {
			if err := setter.setBlob([]byte(b.Value)); err != nil {
				return fmt.Errorf("failed to set blob value: %w", err)
			}
		}
	}

	return nil
}

func newBlob(obj any) *Blob {
	sb := strings.Builder{}
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)

	if err := enc.Encode(obj); err != nil {
		panic("could not marshal object to json")
	}

	return &Blob{
		Value: sb.String(),
	}
}
