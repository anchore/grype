package v6

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnaffectedCPEStore_AddUnaffectedCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newUnaffectedCPEStore(db, bw)

	cpe1 := &UnaffectedCPEHandle{
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
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	cpe2 := testUnaffectedCPEHandle() // vuln id = 2

	err := s.AddUnaffectedCPEs(cpe1, cpe2)
	require.NoError(t, err)

	var result1 UnaffectedCPEHandle
	err = db.Where("cpe_id = ?", 1).First(&result1).Error
	require.NoError(t, err)
	assert.Equal(t, cpe1.VulnerabilityID, result1.VulnerabilityID)
	assert.Equal(t, cpe1.ID, result1.ID)
	assert.Equal(t, cpe1.BlobID, result1.BlobID)
	assert.Nil(t, result1.BlobValue) // since we're not preloading any fields on the fetch

	var result2 UnaffectedCPEHandle
	err = db.Where("cpe_id = ?", 2).First(&result2).Error
	require.NoError(t, err)
	assert.Equal(t, cpe2.VulnerabilityID, result2.VulnerabilityID)
	assert.Equal(t, cpe2.ID, result2.ID)
	assert.Equal(t, cpe2.BlobID, result2.BlobID)
	assert.Nil(t, result2.BlobValue) // since we're not preloading any fields on the fetch
}

func TestUnaffectedCPEStore_GetCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newUnaffectedCPEStore(db, bw)

	c := testUnaffectedCPEHandle()
	err := s.AddUnaffectedCPEs(c)
	require.NoError(t, err)

	results, err := s.GetUnaffectedCPEs(cpeFromProduct(c.CPE.Product), nil)
	require.NoError(t, err)

	expected := []UnaffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)
	assert.Equal(t, c.ID, result.ID)
	assert.Equal(t, c.BlobID, result.BlobID)
	require.Nil(t, result.BlobValue) // since we're not preloading any fields on the fetch

	// fetch again with blob & cpe preloaded
	results, err = s.GetUnaffectedCPEs(cpeFromProduct(c.CPE.Product), &GetCPEOptions{PreloadCPE: true, PreloadBlob: true, PreloadVulnerability: true})
	require.NoError(t, err)
	require.Len(t, results, len(expected))
	result = results[0]
	assert.NotNil(t, result.BlobValue)
	if d := cmp.Diff(*c, result); d != "" {
		t.Errorf("unexpected result (-want +got):\n%s", d)
	}
}

func TestUnaffectedCPEStore_GetExact(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newUnaffectedCPEStore(db, bw)

	c := testUnaffectedCPEHandle()
	err := s.AddUnaffectedCPEs(c)
	require.NoError(t, err)

	// we want to search by all fields to ensure that all are accounted for in the query (since there are string fields referenced in the where clauses)
	results, err := s.GetUnaffectedCPEs(toCPE(c.CPE), nil)
	require.NoError(t, err)

	expected := []UnaffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)

}

func TestUnaffectedCPEStore_Get_CaseInsensitive(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newUnaffectedCPEStore(db, bw)

	c := testUnaffectedCPEHandle()
	err := s.AddUnaffectedCPEs(c)
	require.NoError(t, err)

	// we want to search by all fields to ensure that all are accounted for in the query (since there are string fields referenced in the where clauses)
	results, err := s.GetUnaffectedCPEs(toCPE(&Cpe{
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

	expected := []UnaffectedCPEHandle{*c}
	require.Len(t, results, len(expected))
	result := results[0]
	assert.Equal(t, c.CpeID, result.CpeID)
}

func TestUnaffectedCPEStore_PreventDuplicateCPEs(t *testing.T) {
	db := setupTestStore(t).db
	bw := newBlobStore(db)
	s := newUnaffectedCPEStore(db, bw)

	cpe1 := &UnaffectedCPEHandle{
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
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	err := s.AddUnaffectedCPEs(cpe1)
	require.NoError(t, err)

	// attempt to add a duplicate CPE with the same values
	duplicateCPE := &UnaffectedCPEHandle{
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
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2024-1234"},
		},
	}

	err = s.AddUnaffectedCPEs(duplicateCPE)
	require.NoError(t, err)

	require.Equal(t, cpe1.CpeID, duplicateCPE.CpeID, "expected the CPE DB ID to be the same")

	var existingCPEs []Cpe
	err = db.Find(&existingCPEs).Error
	require.NoError(t, err)
	require.Len(t, existingCPEs, 1, "expected only one CPE to exist")

	actualHandles, err := s.GetUnaffectedCPEs(cpeFromProduct(cpe1.CPE.Product), &GetCPEOptions{
		PreloadCPE:           true,
		PreloadBlob:          true,
		PreloadVulnerability: true,
	})
	require.NoError(t, err)

	// the CPEs should be the same, and the store should reconcile the IDs
	duplicateCPE.CpeID = cpe1.CpeID
	duplicateCPE.CPE.ID = cpe1.CPE.ID

	expected := []UnaffectedCPEHandle{*cpe1, *duplicateCPE}
	require.Len(t, actualHandles, len(expected), "expected both handles to be stored")
	if d := cmp.Diff(expected, actualHandles); d != "" {
		t.Errorf("unexpected result (-want +got):\n%s", d)
	}
}

func testUnaffectedCPEHandle() *UnaffectedCPEHandle {
	return &UnaffectedCPEHandle{
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
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2024-4321"},
		},
	}
}
