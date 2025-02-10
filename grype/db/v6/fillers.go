package v6

import (
	"errors"
)

// fillAffectedPackageHandles lazy loads all properties on the list of AffectedPackageHandles
func fillAffectedPackageHandles(reader Reader, handles []*AffectedPackageHandle) error {
	return errors.Join(
		reader.attachBlobValue(toBlobables(handles)...),
		fillRefs(reader, handles, affectedPackageHandleOperatingSystemRef, operatingSystemID),
		fillRefs(reader, handles, affectedPackageHandlePackageRef, packageID),
		fillVulnerabilityHandles(reader, handles, affectedPackageHandleVulnerabilityHandleRef),
	)
}

func affectedPackageHandleOperatingSystemRef(t *AffectedPackageHandle) idRef[OperatingSystem] {
	return idRef[OperatingSystem]{
		id:  t.OperatingSystemID,
		ref: &t.OperatingSystem,
	}
}

func affectedPackageHandlePackageRef(t *AffectedPackageHandle) idRef[Package] {
	return idRef[Package]{
		id:  &t.PackageID,
		ref: &t.Package,
	}
}

func affectedPackageHandleVulnerabilityHandleRef(t *AffectedPackageHandle) idRef[VulnerabilityHandle] {
	return idRef[VulnerabilityHandle]{
		id:  &t.VulnerabilityID,
		ref: &t.Vulnerability,
	}
}

// fillAffectedCPEHandles lazy loads all properties on the list of AffectedCPEHandles
func fillAffectedCPEHandles(reader Reader, handles []*AffectedCPEHandle) error {
	return errors.Join(
		reader.attachBlobValue(toBlobables(handles)...),
		fillRefs(reader, handles, affectedCPEHandleCpeRef, cpeHandleID),
		fillVulnerabilityHandles(reader, handles, affectedCPEHandleVulnerabilityHandleRef),
	)
}

func affectedCPEHandleCpeRef(t *AffectedCPEHandle) idRef[Cpe] {
	return idRef[Cpe]{
		id:  &t.CpeID,
		ref: &t.CPE,
	}
}

func affectedCPEHandleVulnerabilityHandleRef(t *AffectedCPEHandle) idRef[VulnerabilityHandle] {
	return idRef[VulnerabilityHandle]{
		id:  &t.VulnerabilityID,
		ref: &t.Vulnerability,
	}
}

// fillVulnerabilityHandles lazy loads vulnerability handle properties
func fillVulnerabilityHandles[T any](reader Reader, handles []*T, vulnHandleRef refProvider[T, VulnerabilityHandle]) error {
	// fill vulnerabilities
	if err := fillRefs(reader, handles, vulnHandleRef, vulnerabilityHandleID); err != nil {
		return err
	}
	var providerRefs []ref[string, Provider]
	vulnHandles := make([]*VulnerabilityHandle, len(handles))
	for i := range handles {
		vulnHandles[i] = *vulnHandleRef(handles[i]).ref
		providerRefs = append(providerRefs, ref[string, Provider]{
			id:  &vulnHandles[i].ProviderID,
			ref: &vulnHandles[i].Provider,
		})
	}
	// then get references to them to fill the properties
	return errors.Join(
		reader.attachBlobValue(toBlobables(vulnHandles)...),
		reader.fillProviders(providerRefs),
	)
}

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

func toBlobables[T blobable](handles []T) []blobable {
	out := make([]blobable, len(handles))
	for i := range handles {
		out[i] = handles[i]
	}
	return out
}
