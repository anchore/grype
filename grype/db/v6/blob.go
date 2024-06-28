package v6

import (
	"fmt"
	"github.com/OneOfOne/xxhash"
	"github.com/anchore/grype/internal/log"
)

func BlobDigest(content string) string {
	h := xxhash.New64()
	h.Write([]byte(content))             // TODO: handle error?
	return fmt.Sprintf("%x", h.Sum(nil)) // by the size we can surmise that this is a xxh64 hash
}

type BlobStore interface {
	AddBlobs(blobs ...*Blob) error
	GetBlob(digest string) (*Blob, error)
}

type blobStore struct {
	*StoreConfig
	*state
}

func NewBlobStore(cfg *StoreConfig) BlobStore {
	return &blobStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

func (s *blobStore) GetBlob(digest string) (*Blob, error) {
	log.WithFields("digest", digest).Trace("fetching Blob record")

	var model Blob

	result := s.db.Where("digest = ?", digest).Find(&model)
	return &model, result.Error
}

func (s *blobStore) AddBlobs(blobs ...*Blob) error {
	for _, b := range blobs {
		if err := s.db.FirstOrCreate(b).Error; err != nil {
			return err
		}
	}
	return nil
}
