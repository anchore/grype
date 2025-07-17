package v6

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
)

func TestAffectedCPEStore_AddAffectedCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newAffectedCPEStore(db, bw)

	cpe1 := &AffectedCPEHandle{
		Vulnerability: &VulnerabilityHandle{ // vuln id = 1
			Provider: &Provider{
				ID: "nvd",
			},
			Name: "CVE-2023-5678",
		},
		CPE: &Cpe{
			Part:    "a",
			Vendor:  "vendor-1",
			Product: "product-1",
			Edition: "edition-1",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	cpe2 := testAffectedCPEHandle() // vuln id = 2

	err := s.AddAffectedCPEs(cpe1, cpe2)
	require.NoError(t, err)

	var result1 AffectedCPEHandle
	err = db.Where("cpe_id = ?", 1).First(&result1).Error
	require.NoError(t, err)
	assert.Equal(t, cpe1.VulnerabilityID, result1.VulnerabilityID)
	assert.Equal(t, cpe1.ID, result1.ID)
	assert.Equal(t, cpe1.BlobID, result1.BlobID)
	assert.Nil(t, result1.BlobValue) // since we're not preloading any fields on the fetch

	var result2 AffectedCPEHandle
	err = db.Where("cpe_id = ?", 2).First(&result2).Error
	require.NoError(t, err)
	assert.Equal(t, cpe2.VulnerabilityID, result2.VulnerabilityID)
	assert.Equal(t, cpe2.ID, result2.ID)
	assert.Equal(t, cpe2.BlobID, result2.BlobID)
	assert.Nil(t, result2.BlobValue) // since we're not preloading any fields on the fetch
}

func TestAffectedCPEStore_GetCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newAffectedCPEStore(db, bw)

	c := testAffectedCPEHandle()
	err := s.AddAffectedCPEs(c)
	require.NoError(t, err)

	results, err := s.GetAffectedCPEs(cpeFromProduct(c.CPE.Product), nil)
	require.NoError(t, err)

	expected := []AffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)
	assert.Equal(t, c.ID, result.ID)
	assert.Equal(t, c.BlobID, result.BlobID)
	require.Nil(t, result.BlobValue) // since we're not preloading any fields on the fetch

	// fetch again with blob & cpe preloaded
	results, err = s.GetAffectedCPEs(cpeFromProduct(c.CPE.Product), &GetAffectedCPEOptions{PreloadCPE: true, PreloadBlob: true, PreloadVulnerability: true})
	require.NoError(t, err)
	require.Len(t, results, len(expected))
	result = results[0]
	assert.NotNil(t, result.BlobValue)
	if d := cmp.Diff(*c, result); d != "" {
		t.Errorf("unexpected result (-want +got):\n%s", d)
	}
}

func TestAffectedCPEStore_GetExact(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newAffectedCPEStore(db, bw)

	c := testAffectedCPEHandle()
	err := s.AddAffectedCPEs(c)
	require.NoError(t, err)

	// we want to search by all fields to ensure that all are accounted for in the query (since there are string fields referenced in the where clauses)
	results, err := s.GetAffectedCPEs(toCPE(c.CPE), nil)
	require.NoError(t, err)

	expected := []AffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)

}

func TestAffectedCPEStore_Get_CaseInsensitive(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newAffectedCPEStore(db, bw)

	c := testAffectedCPEHandle()
	err := s.AddAffectedCPEs(c)
	require.NoError(t, err)

	// we want to search by all fields to ensure that all are accounted for in the query (since there are string fields referenced in the where clauses)
	results, err := s.GetAffectedCPEs(toCPE(&Cpe{
		Part:            "Application",      // capitalized
		Vendor:          "Vendor",           // capitalized
		Product:         "Product",          // capitalized
		Edition:         "Edition",          // capitalized
		Language:        "Language",         // capitalized
		SoftwareEdition: "Software_edition", // capitalized
		TargetHardware:  "Target_hardware",  // capitalized
		TargetSoftware:  "Target_software",  // capitalized
		Other:           "Other",            // capitalized
	}), nil)
	require.NoError(t, err)

	expected := []AffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)
}

func TestAffectedCPEStore_PreventDuplicateCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newAffectedCPEStore(db, bw)

	cpe1 := &AffectedCPEHandle{
		Vulnerability: &VulnerabilityHandle{ // vuln id = 1
			Name: "CVE-2023-5678",
			Provider: &Provider{
				ID: "nvd",
			},
		},
		CPE: &Cpe{ // ID = 1
			Part:    "a",
			Vendor:  "vendor-1",
			Product: "product-1",
			Edition: "edition-1",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	err := s.AddAffectedCPEs(cpe1)
	require.NoError(t, err)

	// attempt to add a duplicate CPE with the same values
	duplicateCPE := &AffectedCPEHandle{
		Vulnerability: &VulnerabilityHandle{ // vuln id = 2, different VulnerabilityID for testing...
			Name: "CVE-2024-1234",
			Provider: &Provider{
				ID: "nvd",
			},
		},
		CpeID: 2, // for testing explicitly set to 2, but this is unrealistic
		CPE: &Cpe{
			ID:      2,           // different, again, unrealistic but useful for testing
			Part:    "a",         // same
			Vendor:  "vendor-1",  // same
			Product: "product-1", // same
			Edition: "edition-1", // same
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2024-1234"},
		},
	}

	err = s.AddAffectedCPEs(duplicateCPE)
	require.NoError(t, err)

	require.Equal(t, cpe1.CpeID, duplicateCPE.CpeID, "expected the CPE DB ID to be the same")

	var existingCPEs []Cpe
	err = db.Find(&existingCPEs).Error
	require.NoError(t, err)
	require.Len(t, existingCPEs, 1, "expected only one CPE to exist")

	actualHandles, err := s.GetAffectedCPEs(cpeFromProduct(cpe1.CPE.Product), &GetAffectedCPEOptions{
		PreloadCPE:           true,
		PreloadBlob:          true,
		PreloadVulnerability: true,
	})
	require.NoError(t, err)

	// the CPEs should be the same, and the store should reconcile the IDs
	duplicateCPE.CpeID = cpe1.CpeID
	duplicateCPE.CPE.ID = cpe1.CPE.ID

	expected := []AffectedCPEHandle{*cpe1, *duplicateCPE}
	require.Len(t, actualHandles, len(expected), "expected both handles to be stored")
	if d := cmp.Diff(expected, actualHandles); d != "" {
		t.Errorf("unexpected result (-want +got):\n%s", d)
	}
}

func cpeFromProduct(product string) *cpe.Attributes {
	return &cpe.Attributes{
		Product: product,
	}
}

func toCPE(c *Cpe) *cpe.Attributes {
	return &cpe.Attributes{
		Part:      c.Part,
		Vendor:    c.Vendor,
		Product:   c.Product,
		Edition:   c.Edition,
		Language:  c.Language,
		SWEdition: c.SoftwareEdition,
		TargetSW:  c.TargetSoftware,
		TargetHW:  c.TargetHardware,
		Other:     c.Other,
	}
}

func testAffectedCPEHandle() *AffectedCPEHandle {
	return &AffectedCPEHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2024-4321",
			Provider: &Provider{
				ID: "nvd",
			},
		},
		CPE: &Cpe{
			Part:            "application",
			Vendor:          "vendor",
			Product:         "product",
			Edition:         "edition",
			Language:        "language",
			SoftwareEdition: "software_edition",
			TargetHardware:  "target_hardware",
			TargetSoftware:  "target_software",
			Other:           "other",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2024-4321"},
		},
	}
}
