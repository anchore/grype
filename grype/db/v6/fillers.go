package v6

import (
	"encoding/json"
	"errors"

	"gorm.io/gorm"
)

func fillAffectedCPEHandles(db *gorm.DB, handles []AffectedCPEHandle) error {
	return errors.Join(
		fillRefs(db, handles, affectedCPEVulnerabilityHandleRef, vulnerabilityHandleID),
		fillRefs(db, handles, affectedCPECPERef, cpeHandleID),
		fillBlobs(db, handles, affectedCPEBlobRef),
	)
}

func fillAffectedPackageHandles(db *gorm.DB, handles []AffectedPackageHandle) error {
	// pkgRefs := collectUniqueValues(handles, func(from v6.AffectedPackageHandle) idRef[v6.Package] {
	//	return idRef[v6.Package]{
	//		id:  &from.PackageID,
	//		ref: &from.Package,
	//	}
	// })

	return errors.Join(
		fillRefs(db, handles, affectedPackageVulnerabilityHandleRef, vulnerabilityHandleID),
		fillRefs(db, handles, affectedPackageOperatingSystemHandleRef, operatingSystemID),
		fillRefs(db, handles, affectedPackagePackageHandleRef, packageID),
		fillBlobs(db, handles, affectedPackageBlobRef),
	)
}

func fillBlobs[ContainingType, BlobType any](db *gorm.DB, handles []ContainingType, blobRef refProvider[ContainingType, BlobType]) error {
	for i := range handles {
		ref := blobRef(&handles[i])
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

// func vulnerabilityHandleBlobRef(h *VulnerabilityHandle) idRef[VulnerabilityBlob] {
//	return idRef[VulnerabilityBlob]{
//		id:  &h.BlobID,
//		ref: &h.BlobValue,
//	}
//}
