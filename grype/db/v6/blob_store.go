package v6

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/OneOfOne/xxhash"
)

type blobStore struct {
	*StoreConfig
	*state
}

func newBlobStore(cfg *StoreConfig) *blobStore {
	return &blobStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

//func (s *vulnerabilityStore) GetBlob(id string) ([]VulnerabilityHandle, error) {
//	log.WithFields("name", id).Trace("fetching Blob record")
//
//	panic("not implemented")
//}

func (s *blobStore) AddVulnerabilityBlob(vulnerabilities ...*VulnerabilityHandle) error {
	for _, v := range vulnerabilities {
		if v.BlobValue == nil {
			continue
		}
		bl := newBlob(v.BlobValue)

		if err := s.AddBlobs(bl); err != nil {
			return err
		}

		v.BlobID = bl.ID
	}
	return nil
}

func (s *blobStore) AddAffectedPackageBlob(affected ...*AffectedPackageHandle) error {
	for _, v := range affected {
		if v.BlobValue == nil {
			continue
		}
		bl := newBlob(v.BlobValue)

		if err := s.AddBlobs(bl); err != nil {
			return err
		}

		v.BlobID = bl.ID
	}
	return nil
}

func (s *blobStore) AddAffectedCPEBlob(affected ...*AffectedCPEHandle) error {
	for _, v := range affected {
		if v.BlobValue == nil {
			continue
		}
		bl := newBlob(v.BlobValue)

		if err := s.AddBlobs(bl); err != nil {
			return err
		}

		v.BlobID = bl.ID
	}
	return nil
}

func (s *blobStore) AddBlobs(blobs ...*BlobWithDigest) error {
	for _, v := range blobs {
		if err := s.db.Where("digest = ?", v.Digest).FirstOrCreate(v).Error; err != nil {
			return err
		}

	}
	return nil
}

func newBlob(obj any) *BlobWithDigest {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	err := enc.Encode(obj)
	if err != nil {
		panic("could not encode object as json")
	}
	value := buf.String()
	return &BlobWithDigest{
		Digest: blobDigest(value),
		Value:  value,
	}
}

func blobDigest(content string) string {
	h := xxhash.New64()
	h.Write([]byte(content))                   // TODO: handle error?
	return fmt.Sprintf("xxh64:%x", h.Sum(nil)) // by the size we can surmise that this is a xxh64 hash
}
