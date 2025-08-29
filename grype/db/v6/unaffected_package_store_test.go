package v6

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
)

type unaffectedPackageHandlePreloadConfig struct {
	name                 string
	PreloadOS            bool
	PreloadPackage       bool
	PreloadBlob          bool
	PreloadVulnerability bool
	prepExpectations     func(*testing.T, []UnaffectedPackageHandle) []UnaffectedPackageHandle
}

func defaultUnaffectedPackageHandlePreloadCases() []unaffectedPackageHandlePreloadConfig {
	return []unaffectedPackageHandlePreloadConfig{
		{
			name:                 "preload-all",
			PreloadOS:            true,
			PreloadPackage:       true,
			PreloadBlob:          true,
			PreloadVulnerability: true,
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				for _, a := range in {
					if a.OperatingSystemID != nil {
						require.NotNil(t, a.OperatingSystem)
					}
					require.NotNil(t, a.Package)
					require.NotNil(t, a.BlobValue)
					require.NotNil(t, a.Vulnerability)
				}
				return in
			},
		},
		{
			name: "preload-none",
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				var out []UnaffectedPackageHandle
				for _, a := range in {
					if a.OperatingSystem == nil && a.BlobValue == nil && a.Package == nil && a.Vulnerability == nil {
						t.Skip("preload already matches expectation")
					}
					a.OperatingSystem = nil
					a.Package = nil
					a.BlobValue = nil
					a.Vulnerability = nil
					out = append(out, a)
				}
				return out
			},
		},
		{
			name:      "preload-os-only",
			PreloadOS: true,
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				var out []UnaffectedPackageHandle
				for _, a := range in {
					if a.OperatingSystemID != nil {
						require.NotNil(t, a.OperatingSystem)
					}
					if a.Package == nil && a.BlobValue == nil && a.Vulnerability == nil {
						t.Skip("preload already matches expectation")
					}
					a.Package = nil
					a.BlobValue = nil
					a.Vulnerability = nil
					out = append(out, a)
				}
				return out
			},
		},
		{
			name:           "preload-package-only",
			PreloadPackage: true,
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				var out []UnaffectedPackageHandle
				for _, a := range in {
					require.NotNil(t, a.Package)
					if a.OperatingSystem == nil && a.BlobValue == nil && a.Vulnerability == nil {
						t.Skip("preload already matches expectation")
					}
					a.OperatingSystem = nil
					a.BlobValue = nil
					a.Vulnerability = nil
					out = append(out, a)
				}
				return out
			},
		},
		{
			name:        "preload-blob-only",
			PreloadBlob: true,
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				var out []UnaffectedPackageHandle
				for _, a := range in {
					if a.OperatingSystem == nil && a.Package == nil && a.Vulnerability == nil {
						t.Skip("preload already matches expectation")
					}
					a.OperatingSystem = nil
					a.Package = nil
					a.Vulnerability = nil
					out = append(out, a)
				}
				return out
			},
		},
		{
			name:                 "preload-vulnerability-only",
			PreloadVulnerability: true,
			prepExpectations: func(t *testing.T, in []UnaffectedPackageHandle) []UnaffectedPackageHandle {
				var out []UnaffectedPackageHandle
				for _, a := range in {
					if a.OperatingSystem == nil && a.Package == nil && a.BlobValue == nil {
						t.Skip("preload already matches expectation")
					}
					a.OperatingSystem = nil
					a.Package = nil
					a.BlobValue = nil
					out = append(out, a)
				}
				return out
			},
		},
	}
}

func TestUnaffectedPackageStore_AddUnaffectedPackages(t *testing.T) {
	setupUnaffectedPackageStore := func(t *testing.T) *unaffectedPackageStore {
		db := setupTestStore(t).db
		bs := newBlobStore(db)
		return newUnaffectedPackageStore(db, bs, newOperatingSystemStore(db, bs))
	}

	setupTestStoreWithPackages := func(t *testing.T) (*UnaffectedPackageHandle, *UnaffectedPackageHandle, *unaffectedPackageStore) {
		pkg1 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1"},
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := testDistro1UnaffectedPackage2Handle()

		return pkg1, pkg2, setupUnaffectedPackageStore(t)
	}

	t.Run("no preloading", func(t *testing.T) {
		pkg1, pkg2, s := setupTestStoreWithPackages(t)

		err := s.AddUnaffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var result1 UnaffectedPackageHandle
		err = s.db.Where("package_id = ?", pkg1.PackageID).First(&result1).Error
		require.NoError(t, err)
		assert.Equal(t, pkg1.PackageID, result1.PackageID)
		assert.Equal(t, pkg1.BlobID, result1.BlobID)
		require.Nil(t, result1.BlobValue) // no preloading on fetch

		var result2 UnaffectedPackageHandle
		err = s.db.Where("package_id = ?", pkg2.PackageID).First(&result2).Error
		require.NoError(t, err)
		assert.Equal(t, pkg2.PackageID, result2.PackageID)
		assert.Equal(t, pkg2.BlobID, result2.BlobID)
		require.Nil(t, result2.BlobValue)
	})

	t.Run("preloading", func(t *testing.T) {
		pkg1, pkg2, s := setupTestStoreWithPackages(t)

		err := s.AddUnaffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		options := &GetPackageOptions{
			PreloadOS:      true,
			PreloadPackage: true,
			PreloadBlob:    true,
		}

		results, err := s.GetUnaffectedPackages(pkgFromName(pkg1.Package.Name), options)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		require.NotNil(t, result.Package)
		require.NotNil(t, result.BlobValue)
		assert.Nil(t, result.OperatingSystem) // pkg1 has no OS
	})

	t.Run("preload CPEs", func(t *testing.T) {
		pkg1, _, s := setupTestStoreWithPackages(t)

		c := Cpe{
			Part:    "a",
			Vendor:  "vendor1",
			Product: "product1",
		}
		pkg1.Package.CPEs = []Cpe{c}

		err := s.AddUnaffectedPackages(pkg1)
		require.NoError(t, err)

		options := &GetPackageOptions{
			PreloadPackage:     true,
			PreloadPackageCPEs: true,
		}

		results, err := s.GetUnaffectedPackages(pkgFromName(pkg1.Package.Name), options)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		require.NotNil(t, result.Package)

		// the IDs should have been set, and there is only one, so we know the correct values
		c.ID = 1

		if d := cmp.Diff([]Cpe{c}, result.Package.CPEs); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}
	})

	t.Run("Package deduplication", func(t *testing.T) {
		pkg1 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1"},
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1"}, // same!
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupUnaffectedPackageStore(t)
		err := s.AddUnaffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var pkgs []Package
		err = s.db.Find(&pkgs).Error
		require.NoError(t, err)

		expected := []Package{
			*pkg1.Package,
		}

		if d := cmp.Diff(expected, pkgs); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}
	})

	t.Run("same package with multiple CPEs", func(t *testing.T) {
		cpe1 := Cpe{
			Part:    "a",
			Vendor:  "vendor1",
			Product: "product1",
		}

		cpe2 := Cpe{
			Part:    "a",
			Vendor:  "vendor2",
			Product: "product2",
		}

		pkg1 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1", CPEs: []Cpe{cpe1}},
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-56789",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1", CPEs: []Cpe{cpe1, cpe2}}, // duplicate CPE + additional CPE
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupUnaffectedPackageStore(t)
		err := s.AddUnaffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var pkgs []Package
		err = s.db.Preload("CPEs").Find(&pkgs).Error
		require.NoError(t, err)

		expPkg := *pkg1.Package
		expPkg.ID = 1
		cpe1.ID = 1
		cpe2.ID = 2
		expPkg.CPEs = []Cpe{cpe1, cpe2}

		expected := []Package{
			expPkg,
		}

		if d := cmp.Diff(expected, pkgs); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}

		expectedCPEs := []Cpe{cpe1, cpe2}
		var cpeResults []Cpe
		err = s.db.Find(&cpeResults).Error
		require.NoError(t, err)
		if d := cmp.Diff(expectedCPEs, cpeResults); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}

	})

	t.Run("allow same CPE to belong to multiple packages", func(t *testing.T) {
		cpe1 := Cpe{
			Part:    "a",
			Vendor:  "vendor1",
			Product: "product1",
		}

		cpe2 := Cpe{
			Part:    "a",
			Vendor:  "vendor2",
			Product: "product2",
		}

		pkg1 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Ecosystem: "type1", CPEs: []Cpe{cpe1}},
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &UnaffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-56789",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg2", Ecosystem: "type1", CPEs: []Cpe{cpe1, cpe2}}, // overlapping CPEs for different packages
			BlobValue: &PackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupUnaffectedPackageStore(t)
		err := s.AddUnaffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var pkgs []Package
		err = s.db.Preload("CPEs").Find(&pkgs).Error
		require.NoError(t, err)

		cpe1.ID = 1
		cpe2.ID = 2

		expPkg1 := *pkg1.Package
		expPkg1.ID = 1
		expPkg1.CPEs = []Cpe{cpe1}

		expPkg2 := *pkg2.Package
		expPkg2.ID = 2
		expPkg2.CPEs = []Cpe{cpe1, cpe2}

		expected := []Package{
			expPkg1,
			expPkg2,
		}

		if d := cmp.Diff(expected, pkgs); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}

		expectedCPEs := []Cpe{cpe1, cpe2}
		var cpeResults []Cpe
		err = s.db.Find(&cpeResults).Error
		require.NoError(t, err)
		if d := cmp.Diff(expectedCPEs, cpeResults); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}
	})
}

func TestUnaffectedPackageStore_GetUnaffectedPackages_ByCPE(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)
	s := newUnaffectedPackageStore(db, bs, oss)

	cpe1 := Cpe{Part: "a", Vendor: "vendor1", Product: "product1"}
	cpe2 := Cpe{Part: "a", Vendor: "vendor2", Product: "product2"}
	cpe3 := Cpe{Part: "a", Vendor: "vendor2", Product: "product2", TargetSoftware: "target1"}
	pkg1 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-1234",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg1", Ecosystem: "type1", CPEs: []Cpe{cpe1}},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}
	pkg2 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-5678",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg2", Ecosystem: "type2", CPEs: []Cpe{cpe2}},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	pkg3 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-5678",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg3", Ecosystem: "type2", CPEs: []Cpe{cpe3}},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	err := s.AddUnaffectedPackages(pkg1, pkg2, pkg3)
	require.NoError(t, err)

	tests := []struct {
		name     string
		cpe      cpe.Attributes
		options  *GetPackageOptions
		expected []UnaffectedPackageHandle
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "full match CPE",
			cpe: cpe.Attributes{
				Part:    "a",
				Vendor:  "vendor1",
				Product: "product1",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []UnaffectedPackageHandle{*pkg1},
		},
		{
			name: "partial match CPE",
			cpe: cpe.Attributes{
				Part:   "a",
				Vendor: "vendor2",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []UnaffectedPackageHandle{*pkg2, *pkg3},
		},
		{
			name: "match on any TSW when specific one provided when broad matching enabled",
			cpe: cpe.Attributes{
				Part:     "a",
				Vendor:   "vendor2",
				TargetSW: "target1",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:    true,
				PreloadPackage:        true,
				PreloadBlob:           true,
				PreloadVulnerability:  true,
				AllowBroadCPEMatching: true,
			},
			expected: []UnaffectedPackageHandle{*pkg2, *pkg3},
		},
		{
			name: "do NOT match on any TSW when specific one provided when broad matching disabled",
			cpe: cpe.Attributes{
				Part:     "a",
				Vendor:   "vendor2",
				TargetSW: "target1",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:    true,
				PreloadPackage:        true,
				PreloadBlob:           true,
				PreloadVulnerability:  true,
				AllowBroadCPEMatching: false,
			},
			expected: []UnaffectedPackageHandle{*pkg3},
		},
		{
			name: "missing attributes",
			cpe: cpe.Attributes{
				Part: "a",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []UnaffectedPackageHandle{*pkg1, *pkg2, *pkg3},
		},
		{
			name: "no matches",
			cpe: cpe.Attributes{
				Part:    "a",
				Vendor:  "unknown_vendor",
				Product: "unknown_product",
			},
			options: &GetPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			result, err := s.GetUnaffectedPackages(&PackageSpecifier{CPE: &tt.cpe}, tt.options)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			if d := cmp.Diff(tt.expected, result, cmpopts.EquateEmpty()); d != "" {
				t.Errorf("unexpected result: %s", d)
			}
		})
	}
}

func TestUnaffectedPackageStore_GetUnaffectedPackages_CaseInsensitive(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)
	s := newUnaffectedPackageStore(db, bs, oss)

	cpe1 := Cpe{Part: "a", Vendor: "Vendor1", Product: "Product1"} // capitalized
	pkg1 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-1234",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		OperatingSystem: &OperatingSystem{
			Name:         "Ubuntu", // capitalized
			ReleaseID:    "zubuntu",
			MajorVersion: "20",
			MinorVersion: "04", // leading 0
			Codename:     "focal",
		},
		Package: &Package{Name: "Pkg1", Ecosystem: "Type1", CPEs: []Cpe{cpe1}}, // capitalized
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}

	pkg2 := &UnaffectedPackageHandle{ // this should never register as a match
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2222-2222",
			Provider: &Provider{
				ID: "provider2",
			},
		},
		OperatingSystem: &OperatingSystem{
			Name:         "ubuntu",
			ReleaseID:    "ubuntu",
			MajorVersion: "20",
			MinorVersion: "10",
		},
		Package: &Package{Name: "pkg2", Ecosystem: "type2"},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2222-2222"},
		},
	}

	err := s.AddUnaffectedPackages(pkg1, pkg2)
	require.NoError(t, err)

	tests := []struct {
		name     string
		pkgSpec  *PackageSpecifier
		options  *GetPackageOptions
		expected int
	}{
		{
			name:     "sanity check: search miss",
			pkgSpec:  pkgFromName("does not exist"),
			expected: 0,
		},
		{
			name:     "get by name",
			pkgSpec:  pkgFromName("pKG1"),
			expected: 1,
		},
		{
			name: "get by CPE",
			pkgSpec: &PackageSpecifier{
				CPE: &cpe.Attributes{Part: "a", Vendor: "veNDor1", Product: "pRODuct1"},
			},
			expected: 1,
		},
		{
			name: "get by ecosystem",
			pkgSpec: &PackageSpecifier{
				Ecosystem: "tYPE1",
			},
			expected: 1,
		},
		{
			name: "get by OS name and version (leading 0)",
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name:         "uBUNtu",
					MajorVersion: "20",
					MinorVersion: "04",
				}},
			},
			expected: 1,
		},
		{
			name: "get by OS name and version",
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name:         "uBUNtu",
					MajorVersion: "20",
					MinorVersion: "4",
				}},
			},
			expected: 1,
		},
		{
			name: "get by OS release",
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name: "zUBuntu",
				}},
			},
			expected: 1,
		},
		{
			name: "get by OS codename",
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					LabelVersion: "fOCAL",
				}},
			},
			expected: 1,
		},
		{
			name: "get by vuln ID",
			options: &GetPackageOptions{
				Vulnerabilities: []VulnerabilitySpecifier{{Name: "cVe-2023-1234"}},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := s.GetUnaffectedPackages(tt.pkgSpec, tt.options)
			require.NoError(t, err)
			require.Len(t, result, tt.expected)
			if tt.expected > 0 {
				assert.Equal(t, pkg1.PackageID, result[0].PackageID)
			}
		})
	}
}

func TestUnaffectedPackageStore_GetUnaffectedPackages_MultipleVulnerabilitySpecs(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)
	s := newUnaffectedPackageStore(db, bs, oss)

	cpe1 := Cpe{Part: "a", Vendor: "vendor1", Product: "product1"}
	cpe2 := Cpe{Part: "a", Vendor: "vendor2", Product: "product2"}
	pkg1 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-1234",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg1", Ecosystem: "type1", CPEs: []Cpe{cpe1}},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}
	pkg2 := &UnaffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-5678",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg2", Ecosystem: "type2", CPEs: []Cpe{cpe2}},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	err := s.AddUnaffectedPackages(pkg1, pkg2)
	require.NoError(t, err)

	result, err := s.GetUnaffectedPackages(nil, &GetPackageOptions{
		PreloadVulnerability: true,
		Vulnerabilities: []VulnerabilitySpecifier{
			{Name: "CVE-2023-1234"},
			{Name: "CVE-2023-5678"},
		},
	})
	require.NoError(t, err)

	actualVulns := strset.New()
	for _, r := range result {
		actualVulns.Add(r.Vulnerability.Name)
	}

	expectedVulns := strset.New("CVE-2023-1234", "CVE-2023-5678")

	assert.ElementsMatch(t, expectedVulns.List(), actualVulns.List())

}

func TestUnaffectedPackageStore_GetUnaffectedPackages(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)
	s := newUnaffectedPackageStore(db, bs, oss)

	pkg2d1 := testDistro1UnaffectedPackage2Handle()
	pkg2 := testNonDistroUnaffectedPackage2Handle()
	pkg2d2 := testDistro2UnaffectedPackage2Handle()
	err := s.AddUnaffectedPackages(pkg2d1, pkg2, pkg2d2)
	require.NoError(t, err)

	tests := []struct {
		name     string
		pkg      *PackageSpecifier
		options  *GetPackageOptions
		expected []UnaffectedPackageHandle
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "specific distro",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name:         "ubuntu",
					MajorVersion: "20",
					MinorVersion: "04",
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1},
		},
		{
			name: "distro major version only",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name:         "ubuntu",
					MajorVersion: "20",
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1, *pkg2d2},
		},
		{
			name: "distro codename",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{{
					Name:         "ubuntu",
					LabelVersion: "groovy",
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d2},
		},
		{
			name: "no distro",
			pkg:  pkgFromName(pkg2.Package.Name),
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{NoOSSpecified},
			},
			expected: []UnaffectedPackageHandle{*pkg2},
		},
		{
			name: "any distro",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				OSs: []*OSSpecifier{AnyOSSpecified},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1, *pkg2, *pkg2d2},
		},
		{
			name:     "package type",
			pkg:      &PackageSpecifier{Name: pkg2.Package.Name, Ecosystem: "type2"},
			expected: []UnaffectedPackageHandle{*pkg2},
		},
		{
			name: "specific CVE",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				Vulnerabilities: []VulnerabilitySpecifier{{
					Name: "CVE-2023-1234",
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1},
		},
		{
			name: "any CVE published after a date",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				Vulnerabilities: []VulnerabilitySpecifier{{
					PublishedAfter: func() *time.Time {
						now := time.Date(2020, 1, 1, 1, 1, 1, 0, time.UTC)
						return &now
					}(),
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1, *pkg2d2},
		},
		{
			name: "any CVE modified after a date",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				Vulnerabilities: []VulnerabilitySpecifier{{
					ModifiedAfter: func() *time.Time {
						now := time.Date(2023, 1, 1, 3, 4, 5, 0, time.UTC).Add(time.Hour * 2)
						return &now
					}(),
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1},
		},
		{
			name: "any rejected CVE",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetPackageOptions{
				Vulnerabilities: []VulnerabilitySpecifier{{
					Status: VulnerabilityRejected,
				}},
			},
			expected: []UnaffectedPackageHandle{*pkg2d1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			for _, pc := range defaultUnaffectedPackageHandlePreloadCases() {
				t.Run(pc.name, func(t *testing.T) {
					opts := tt.options
					if opts == nil {
						opts = &GetPackageOptions{}
					}
					opts.PreloadOS = pc.PreloadOS
					opts.PreloadPackage = pc.PreloadPackage
					opts.PreloadBlob = pc.PreloadBlob
					opts.PreloadVulnerability = pc.PreloadVulnerability
					expected := tt.expected
					if pc.prepExpectations != nil {
						expected = pc.prepExpectations(t, expected)
					}
					result, err := s.GetUnaffectedPackages(tt.pkg, opts)
					tt.wantErr(t, err)
					if err != nil {
						return
					}
					if d := cmp.Diff(expected, result); d != "" {
						t.Errorf("unexpected result: %s", d)
					}
				})
			}
		})
	}
}

func TestUnaffectedPackageStore_ApplyPackageAlias(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)
	s := newUnaffectedPackageStore(db, bs, oss)

	tests := []struct {
		name     string
		input    *PackageSpecifier
		expected string
	}{
		// positive cases
		{name: "alias cocoapods", input: &PackageSpecifier{Ecosystem: "cocoapods"}, expected: "pod"},
		{name: "alias pub", input: &PackageSpecifier{Ecosystem: "pub"}, expected: "dart-pub"},
		{name: "alias otp", input: &PackageSpecifier{Ecosystem: "otp"}, expected: "erlang-otp"},
		{name: "alias github", input: &PackageSpecifier{Ecosystem: "github"}, expected: "github-action"},
		{name: "alias golang", input: &PackageSpecifier{Ecosystem: "golang"}, expected: "go-module"},
		{name: "alias maven", input: &PackageSpecifier{Ecosystem: "maven"}, expected: "java-archive"},
		{name: "alias composer", input: &PackageSpecifier{Ecosystem: "composer"}, expected: "php-composer"},
		{name: "alias pecl", input: &PackageSpecifier{Ecosystem: "pecl"}, expected: "php-pecl"},
		{name: "alias pypi", input: &PackageSpecifier{Ecosystem: "pypi"}, expected: "python"},
		{name: "alias cran", input: &PackageSpecifier{Ecosystem: "cran"}, expected: "R-package"},
		{name: "alias luarocks", input: &PackageSpecifier{Ecosystem: "luarocks"}, expected: "lua-rocks"},
		{name: "alias cargo", input: &PackageSpecifier{Ecosystem: "cargo"}, expected: "rust-crate"},

		// negative cases
		{name: "generic type", input: &PackageSpecifier{Ecosystem: "generic/linux-kernel"}, expected: "generic/linux-kernel"},
		{name: "empty ecosystem", input: &PackageSpecifier{Ecosystem: ""}, expected: ""},
		{name: "matching type", input: &PackageSpecifier{Ecosystem: "python"}, expected: "python"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.pkgStore.applyPackageAlias(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, tt.input.Ecosystem)
		})
	}
}

func testDistro1UnaffectedPackage2Handle() *UnaffectedPackageHandle {
	now := time.Date(2023, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &UnaffectedPackageHandle{
		Package: &Package{
			Name:      "pkg2",
			Ecosystem: "type2d",
		},
		Vulnerability: &VulnerabilityHandle{
			Name:          "CVE-2023-1234",
			Status:        VulnerabilityRejected,
			PublishedDate: &now,
			ModifiedDate:  &later,
			Provider: &Provider{
				ID: "ubuntu",
			},
		},
		OperatingSystem: &OperatingSystem{
			Name:         "ubuntu",
			MajorVersion: "20",
			MinorVersion: "04",
			LabelVersion: "focal",
		},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}
}

func testDistro2UnaffectedPackage2Handle() *UnaffectedPackageHandle {
	now := time.Date(2020, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &UnaffectedPackageHandle{
		Package: &Package{
			Name:      "pkg2",
			Ecosystem: "type2d",
		},
		Vulnerability: &VulnerabilityHandle{
			Name:          "CVE-2023-4567",
			PublishedDate: &now,
			ModifiedDate:  &later,
			Provider: &Provider{
				ID: "ubuntu",
			},
		},
		OperatingSystem: &OperatingSystem{
			Name:         "ubuntu",
			MajorVersion: "20",
			MinorVersion: "10",
			LabelVersion: "groovy",
		},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}

func testNonDistroUnaffectedPackage2Handle() *UnaffectedPackageHandle {
	now := time.Date(2005, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &UnaffectedPackageHandle{
		Package: &Package{
			Name:      "pkg2",
			Ecosystem: "type2",
		},
		Vulnerability: &VulnerabilityHandle{
			Name:          "CVE-2023-4567",
			PublishedDate: &now,
			ModifiedDate:  &later,
			Provider: &Provider{
				ID: "wolfi",
			},
		},
		BlobValue: &PackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}
