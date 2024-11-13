package v6

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type blobable interface {
	getBlobValue() any
	setBlobID(ID)
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

func (s *blobStore) getBlobValue(id ID) (string, error) {
	var blob Blob
	if err := s.db.First(&blob, id).Error; err != nil {
		return "", err
	}
	return blob.Value, nil
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
