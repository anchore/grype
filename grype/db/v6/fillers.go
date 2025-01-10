package v6

import (
	"encoding/json"
	"errors"

	"gorm.io/gorm"
)

func affectedCPEVulnerabilityHandles(affectedPackages []*AffectedCPEHandle) []*VulnerabilityHandle {
	var out []*VulnerabilityHandle
	for _, h := range affectedPackages {
		if h == nil {
			continue
		}
		out = append(out, h.Vulnerability)
	}
	return out
}

func affectedPackageVulnerabilityHandles(affectedPackages []*AffectedPackageHandle) []*VulnerabilityHandle {
	var out []*VulnerabilityHandle
	for _, h := range affectedPackages {
		if h == nil {
			continue
		}
		out = append(out, h.Vulnerability)
	}
	return out
}

func (s vulnerabilityProvider) fillAffectedCPEHandles(handles []*AffectedCPEHandle) error {
	return errors.Join(
		fillRefs(s.db, handles, affectedCPEVulnerabilityHandleRef, vulnerabilityHandleID),
		fillRefs(s.db, handles, affectedCPECPERef, cpeHandleID),
		fillBlobs(s.db, handles, affectedCPEBlobRef),
	)
}

func fillAffectedPackageBlobs(db *gorm.DB, handles []*AffectedPackageHandle) error {
	return fillBlobs(db, handles, affectedPackageBlobRef)
}

func fillAffectedPackageHandles(db *gorm.DB, handles []*AffectedPackageHandle) error {
	return errors.Join(
		fillAffectedPackageBlobs(db, handles),
		fillRefs(db, handles, affectedPackageVulnerabilityHandleRef, vulnerabilityHandleID),
		fillRefs(db, handles, affectedPackageOperatingSystemHandleRef, operatingSystemID),
		fillRefs(db, handles, affectedPackagePackageHandleRef, packageID),
	)
}

func (s vulnerabilityProvider) fillVulnerabilityHandles(handles []*VulnerabilityHandle) error {
	return errors.Join(
		s.fillProviders(handles),
		fillBlobs(s.db, handles, vulnerabilityHandleBlobRef),
	)
}

func fillBlobs[ContainingType, BlobType any](db *gorm.DB, handles []*ContainingType, blobRef refProvider[ContainingType, BlobType]) error {
	for i := range handles {
		ref := blobRef(handles[i])
		// if no ID or if the blob is already set, do nothing
		if ref.id == nil || *ref.ref != nil {
			continue
		}
		var blob Blob
		err := db.First(&blob, *ref.id).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return err
		}

		var t BlobType
		err = json.Unmarshal([]byte(blob.Value), &t)
		if err != nil {
			return err
		}
		*ref.ref = &t
	}
	return nil
}

func affectedCPECPERef(t *AffectedCPEHandle) idRef[Cpe] {
	return idRef[Cpe]{
		id:  &t.CpeID,
		ref: &t.CPE,
	}
}

func affectedCPEVulnerabilityHandleRef(t *AffectedCPEHandle) idRef[VulnerabilityHandle] {
	return idRef[VulnerabilityHandle]{
		id:  &t.VulnerabilityID,
		ref: &t.Vulnerability,
	}
}

func affectedPackageVulnerabilityHandleRef(t *AffectedPackageHandle) idRef[VulnerabilityHandle] {
	return idRef[VulnerabilityHandle]{
		id:  &t.VulnerabilityID,
		ref: &t.Vulnerability,
	}
}

func affectedPackageOperatingSystemHandleRef(t *AffectedPackageHandle) idRef[OperatingSystem] {
	return idRef[OperatingSystem]{
		id:  t.OperatingSystemID,
		ref: &t.OperatingSystem,
	}
}

func affectedPackagePackageHandleRef(t *AffectedPackageHandle) idRef[Package] {
	return idRef[Package]{
		id:  &t.PackageID,
		ref: &t.Package,
	}
}

// func affectedCPEHandleID(h AffectedCPEHandle) ID {
//	return h.ID
//}

// func vulnerabilityBlobID(h *VulnerabilityHandle) ID {
//	return h.BlobID
//}

func vulnerabilityHandleID(h *VulnerabilityHandle) ID {
	return h.ID
}

func cpeHandleID(h *Cpe) ID {
	return h.ID
}

func operatingSystemID(h *OperatingSystem) ID {
	return h.ID
}

func packageID(h *Package) ID {
	return h.ID
}

func affectedCPEBlobRef(h *AffectedCPEHandle) idRef[AffectedPackageBlob] {
	return idRef[AffectedPackageBlob]{
		id:  &h.BlobID,
		ref: &h.BlobValue,
	}
}

func affectedPackageBlobRef(h *AffectedPackageHandle) idRef[AffectedPackageBlob] {
	return idRef[AffectedPackageBlob]{
		id:  &h.BlobID,
		ref: &h.BlobValue,
	}
}

func vulnerabilityHandleBlobRef(h *VulnerabilityHandle) idRef[VulnerabilityBlob] {
	return idRef[VulnerabilityBlob]{
		id:  &h.BlobID,
		ref: &h.BlobValue,
	}
}
