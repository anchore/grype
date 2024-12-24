package v6

import (
	"encoding/json"
	"errors"
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
	db *gorm.DB
}

func newBlobStore(db *gorm.DB) *blobStore {
	return &blobStore{
		db: db,
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

		var blobDigest BlobDigest
		err := s.db.Where("id = ?", digest).First(&blobDigest).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to get blob digest: %w", err)
		}

		if blobDigest.BlobID != 0 {
			v.ID = blobDigest.BlobID
			continue
		}

		if err := s.db.Create(v).Error; err != nil {
			return fmt.Errorf("failed to create blob: %w", err)
		}

		blobDigest = BlobDigest{
			ID:     digest,
			BlobID: v.ID,
		}
		if err := s.db.Create(blobDigest).Error; err != nil {
			return fmt.Errorf("failed to create blob digest: %w", err)
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
		if id == 0 {
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

func (s *blobStore) Close() error {
	var count int64
	if err := s.db.Model(&Blob{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count blobs: %w", err)
	}

	log.WithFields("records", count).Trace("finalizing blobs")

	// we use the blob_digests table when writing entries to ensure we have unique blobs, but for distribution this
	// is no longer needed and saves on space considerably. For this reason, we drop the table after we are
	// done writing blobs so that the DB is always in a distributable state.
	if err := s.db.Exec("DROP TABLE blob_digests").Error; err != nil {
		return fmt.Errorf("failed to drop blob digests: %w", err)
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
