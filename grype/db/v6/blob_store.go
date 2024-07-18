package v6

import (
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
		v.Blob = newBlob(v.BlobValue)
		return s.AddBlobs(v.Blob)

	}
	return nil
}

func (s *blobStore) AddAffectedPackageBlob(affected ...*AffectedPackageHandle) error {
	for _, v := range affected {
		if v.BlobValue == nil {
			continue
		}
		v.Blob = newBlob(v.BlobValue)
		return s.AddBlobs(v.Blob)

	}
	return nil
}

func (s *blobStore) AddAffectedCPEBlob(affected ...*AffectedCPEHandle) error {
	for _, v := range affected {
		if v.BlobValue == nil {
			continue
		}
		v.Blob = newBlob(v.BlobValue)
		return s.AddBlobs(v.Blob)

	}
	return nil
}

func (s *blobStore) AddBlobs(blobs ...*Blob) error {
	for _, v := range blobs {
		if err := s.db.Where("digest = ?", v.Digest).FirstOrCreate(v).Error; err != nil {
			return err
		}

	}
	return nil
}

func newBlob(obj any) *Blob {
	by, err := json.Marshal(obj)
	if err != nil {
		panic("could not marshal object to json")
	}
	return &Blob{
		Digest: blobDigest(string(by)),
		Value:  string(by),
	}
}

func blobDigest(content string) string {
	h := xxhash.New64()
	h.Write([]byte(content))                   // TODO: handle error?
	return fmt.Sprintf("xxh64:%x", h.Sum(nil)) // by the size we can surmise that this is a xxh64 hash
}
