package v6

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
)

type affectedPackageHandlePreloadConfig struct {
	name                 string
	PreloadOS            bool
	PreloadPackage       bool
	PreloadBlob          bool
	PreloadVulnerability bool
	prepExpectations     func(*testing.T, []AffectedPackageHandle) []AffectedPackageHandle
}

func defaultAffectedPackageHandlePreloadCases() []affectedPackageHandlePreloadConfig {
	return []affectedPackageHandlePreloadConfig{
		{
			name:                 "preload-all",
			PreloadOS:            true,
			PreloadPackage:       true,
			PreloadBlob:          true,
			PreloadVulnerability: true,
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
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
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
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
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
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
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
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
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
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
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
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

func TestAffectedPackageStore_AddAffectedPackages(t *testing.T) {
	setupAffectedPackageStore := func(t *testing.T) *affectedPackageStore {
		db := setupTestStore(t).db
		return newAffectedPackageStore(db, newBlobStore(db))
	}

	setupTestStoreWithPackages := func(t *testing.T) (*AffectedPackageHandle, *AffectedPackageHandle, *affectedPackageStore) {
		pkg1 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1"},
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := testDistro1AffectedPackage2Handle()

		return pkg1, pkg2, setupAffectedPackageStore(t)
	}

	t.Run("no preloading", func(t *testing.T) {
		pkg1, pkg2, s := setupTestStoreWithPackages(t)

		err := s.AddAffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var result1 AffectedPackageHandle
		err = s.db.Where("package_id = ?", pkg1.PackageID).First(&result1).Error
		require.NoError(t, err)
		assert.Equal(t, pkg1.PackageID, result1.PackageID)
		assert.Equal(t, pkg1.BlobID, result1.BlobID)
		require.Nil(t, result1.BlobValue) // no preloading on fetch

		var result2 AffectedPackageHandle
		err = s.db.Where("package_id = ?", pkg2.PackageID).First(&result2).Error
		require.NoError(t, err)
		assert.Equal(t, pkg2.PackageID, result2.PackageID)
		assert.Equal(t, pkg2.BlobID, result2.BlobID)
		require.Nil(t, result2.BlobValue)
	})

	t.Run("preloading", func(t *testing.T) {
		pkg1, pkg2, s := setupTestStoreWithPackages(t)

		err := s.AddAffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		options := &GetAffectedPackageOptions{
			PreloadOS:      true,
			PreloadPackage: true,
			PreloadBlob:    true,
		}

		results, err := s.GetAffectedPackages(pkgFromName(pkg1.Package.Name), options)
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

		err := s.AddAffectedPackages(pkg1)
		require.NoError(t, err)

		options := &GetAffectedPackageOptions{
			PreloadPackage:     true,
			PreloadPackageCPEs: true,
		}

		results, err := s.GetAffectedPackages(pkgFromName(pkg1.Package.Name), options)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		require.NotNil(t, result.Package)

		// the IDs should have been set, and there is only one, so we know the correct values
		c.ID = 1
		c.PackageID = idRef(1)

		if d := cmp.Diff([]Cpe{c}, result.Package.CPEs); d != "" {
			t.Errorf("unexpected result (-want +got):\n%s", d)
		}
	})

	t.Run("Package deduplication", func(t *testing.T) {
		pkg1 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1"},
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1"}, // same!
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupAffectedPackageStore(t)
		err := s.AddAffectedPackages(pkg1, pkg2)
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

		pkg1 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1", CPEs: []Cpe{cpe1}},
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-56789",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1", CPEs: []Cpe{cpe1, cpe2}}, // duplicate CPE + additional CPE
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupAffectedPackageStore(t)
		err := s.AddAffectedPackages(pkg1, pkg2)
		require.NoError(t, err)

		var pkgs []Package
		err = s.db.Preload("CPEs").Find(&pkgs).Error
		require.NoError(t, err)

		expPkg := *pkg1.Package
		expPkg.ID = 1
		cpe1.ID = 1
		cpe1.PackageID = idRef(1)
		cpe2.ID = 2
		cpe2.PackageID = idRef(1)
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

	t.Run("dont allow same CPE to belong to multiple packages", func(t *testing.T) {
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

		pkg1 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-1234",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg1", Type: "type1", CPEs: []Cpe{cpe1}},
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-1234"},
			},
		}

		pkg2 := &AffectedPackageHandle{
			Vulnerability: &VulnerabilityHandle{
				Name: "CVE-2023-56789",
				Provider: &Provider{
					ID: "provider1",
				},
			},
			Package: &Package{Name: "pkg2", Type: "type1", CPEs: []Cpe{cpe1, cpe2}}, // overlapping CPEs for different packages
			BlobValue: &AffectedPackageBlob{
				CVEs: []string{"CVE-2023-56789"},
			},
		}

		s := setupAffectedPackageStore(t)
		err := s.AddAffectedPackages(pkg1, pkg2)
		require.ErrorContains(t, err, "CPE already exists for a different package")
	})
}

func TestAffectedPackageStore_GetAffectedPackages_ByCPE(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	s := newAffectedPackageStore(db, bs)

	cpe1 := Cpe{Part: "a", Vendor: "vendor1", Product: "product1"}
	cpe2 := Cpe{Part: "a", Vendor: "vendor2", Product: "product2"}
	pkg1 := &AffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-1234",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg1", Type: "type1", CPEs: []Cpe{cpe1}},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}
	pkg2 := &AffectedPackageHandle{
		Vulnerability: &VulnerabilityHandle{
			Name: "CVE-2023-5678",
			Provider: &Provider{
				ID: "provider1",
			},
		},
		Package: &Package{Name: "pkg2", Type: "type2", CPEs: []Cpe{cpe2}},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-5678"},
		},
	}

	err := s.AddAffectedPackages(pkg1, pkg2)
	require.NoError(t, err)

	tests := []struct {
		name     string
		cpe      cpe.Attributes
		options  *GetAffectedPackageOptions
		expected []AffectedPackageHandle
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "full match CPE",
			cpe: cpe.Attributes{
				Part:    "a",
				Vendor:  "vendor1",
				Product: "product1",
			},
			options: &GetAffectedPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []AffectedPackageHandle{*pkg1},
		},
		{
			name: "partial match CPE",
			cpe: cpe.Attributes{
				Part:   "a",
				Vendor: "vendor2",
			},
			options: &GetAffectedPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []AffectedPackageHandle{*pkg2},
		},
		{
			name: "missing attributes",
			cpe: cpe.Attributes{
				Part: "a",
			},
			options: &GetAffectedPackageOptions{
				PreloadPackageCPEs:   true,
				PreloadPackage:       true,
				PreloadBlob:          true,
				PreloadVulnerability: true,
			},
			expected: []AffectedPackageHandle{*pkg1, *pkg2},
		},
		{
			name: "no matches",
			cpe: cpe.Attributes{
				Part:    "a",
				Vendor:  "unknown_vendor",
				Product: "unknown_product",
			},
			options: &GetAffectedPackageOptions{
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

			result, err := s.GetAffectedPackages(&PackageSpecifier{CPE: &tt.cpe}, tt.options)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			if d := cmp.Diff(tt.expected, result, cmpopts.EquateEmpty()); d != "" {
				t.Errorf(fmt.Sprintf("unexpected result: %s", d))
			}

		})
	}
}

func TestAffectedPackageStore_GetAffectedPackages(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	s := newAffectedPackageStore(db, bs)

	pkg2d1 := testDistro1AffectedPackage2Handle()
	pkg2d2 := testDistro2AffectedPackage2Handle()
	pkg2 := testNonDistroAffectedPackage2Handle()
	err := s.AddAffectedPackages(pkg2d1, pkg2, pkg2d2)
	require.NoError(t, err)

	tests := []struct {
		name     string
		pkg      *PackageSpecifier
		options  *GetAffectedPackageOptions
		expected []AffectedPackageHandle
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "specific distro",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:         "ubuntu",
					MajorVersion: "20",
					MinorVersion: "04",
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1},
		},
		{
			name: "distro major version only (allow multiple)",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:          "ubuntu",
					MajorVersion:  "20",
					AllowMultiple: true,
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1, *pkg2d2},
		},
		{
			name: "distro major version only (default)",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:          "ubuntu",
					MajorVersion:  "20",
					AllowMultiple: false,
				},
			},
			wantErr: expectErrIs(t, ErrMultipleOSMatches),
		},
		{
			name: "distro codename",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:     "ubuntu",
					Codename: "groovy",
				},
			},
			expected: []AffectedPackageHandle{*pkg2d2},
		},
		{
			name: "no distro",
			pkg:  pkgFromName(pkg2.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: NoDistroSpecified,
			},
			expected: []AffectedPackageHandle{*pkg2},
		},
		{
			name: "any distro",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Distro: AnyDistroSpecified,
			},
			expected: []AffectedPackageHandle{*pkg2d1, *pkg2, *pkg2d2},
		},
		{
			name:     "package type",
			pkg:      &PackageSpecifier{Name: pkg2.Package.Name, Type: "type2"},
			expected: []AffectedPackageHandle{*pkg2},
		},
		{
			name: "specific CVE",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Vulnerability: &VulnerabilitySpecifier{
					Name: "CVE-2023-1234",
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1},
		},
		{
			name: "any CVE published after a date",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Vulnerability: &VulnerabilitySpecifier{
					PublishedAfter: func() *time.Time {
						now := time.Date(2020, 1, 1, 1, 1, 1, 0, time.UTC)
						return &now
					}(),
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1, *pkg2d2},
		},
		{
			name: "any CVE modified after a date",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Vulnerability: &VulnerabilitySpecifier{
					ModifiedAfter: func() *time.Time {
						now := time.Date(2023, 1, 1, 3, 4, 5, 0, time.UTC).Add(time.Hour * 2)
						return &now
					}(),
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1},
		},
		{
			name: "any rejected CVE",
			pkg:  pkgFromName(pkg2d1.Package.Name),
			options: &GetAffectedPackageOptions{
				Vulnerability: &VulnerabilitySpecifier{
					Status: VulnerabilityRejected,
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			for _, pc := range defaultAffectedPackageHandlePreloadCases() {
				t.Run(pc.name, func(t *testing.T) {
					opts := tt.options
					if opts == nil {
						opts = &GetAffectedPackageOptions{}
					}
					opts.PreloadOS = pc.PreloadOS
					opts.PreloadPackage = pc.PreloadPackage
					opts.PreloadBlob = pc.PreloadBlob
					opts.PreloadVulnerability = pc.PreloadVulnerability
					expected := tt.expected
					if pc.prepExpectations != nil {
						expected = pc.prepExpectations(t, expected)
					}
					result, err := s.GetAffectedPackages(tt.pkg, opts)
					tt.wantErr(t, err)
					if err != nil {
						return
					}
					if d := cmp.Diff(expected, result); d != "" {
						t.Errorf(fmt.Sprintf("unexpected result: %s", d))
					}
				})
			}
		})
	}
}

func TestAffectedPackageStore_ResolveDistro(t *testing.T) {
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	s := newAffectedPackageStore(db, bs)

	aliases := []OperatingSystemAlias{
		{Name: "centos", ReplacementName: strRef("rhel")},
		{Name: "rocky", ReplacementName: strRef("rhel")},
		{Name: "alpine", VersionPattern: ".*_alpha.*", ReplacementLabelVersion: strRef("edge"), Rolling: true},
		{Name: "wolfi", Rolling: true},
		{Name: "arch", Rolling: true},
		{Name: "debian", Codename: "trixie", Rolling: true}, // is currently sid, which is considered rolling
	}
	require.NoError(t, db.Create(&aliases).Error)

	ubuntu2004 := &OperatingSystem{Name: "ubuntu", MajorVersion: "20", MinorVersion: "04", Codename: "focal"}
	ubuntu2010 := &OperatingSystem{Name: "ubuntu", MajorVersion: "20", MinorVersion: "10", Codename: "groovy"}
	rhel8 := &OperatingSystem{Name: "rhel", MajorVersion: "8"}
	rhel81 := &OperatingSystem{Name: "rhel", MajorVersion: "8", MinorVersion: "1"}
	debian10 := &OperatingSystem{Name: "debian", MajorVersion: "10"}
	alpine318 := &OperatingSystem{Name: "alpine", MajorVersion: "3", MinorVersion: "18"}
	alpineEdge := &OperatingSystem{Name: "alpine", LabelVersion: "edge"}
	debianTrixie := &OperatingSystem{Name: "debian", Codename: "trixie"}
	debian7 := &OperatingSystem{Name: "debian", MajorVersion: "7", Codename: "wheezy"}
	wolfi := &OperatingSystem{Name: "wolfi", MajorVersion: "20230201"}
	arch := &OperatingSystem{Name: "arch", MajorVersion: "20241110", MinorVersion: "0"}

	operatingSystems := []*OperatingSystem{
		ubuntu2004,
		ubuntu2010,
		rhel8,
		rhel81,
		debian10,
		alpine318,
		alpineEdge,
		debianTrixie,
		debian7,
		wolfi,
		arch,
	}
	require.NoError(t, db.Create(&operatingSystems).Error)

	tests := []struct {
		name      string
		distro    DistroSpecifier
		expected  []OperatingSystem
		expectErr require.ErrorAssertionFunc
	}{
		{
			name: "specific distro with major and minor version",
			distro: DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "alias resolution with major version",
			distro: DistroSpecifier{
				Name:         "centos",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "alias resolution with major and minor version",
			distro: DistroSpecifier{
				Name:         "centos",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			expected: []OperatingSystem{*rhel81},
		},
		{
			name: "distro with major version only",
			distro: DistroSpecifier{
				Name:         "debian",
				MajorVersion: "10",
			},
			expected: []OperatingSystem{*debian10},
		},
		{
			name: "codename resolution",
			distro: DistroSpecifier{
				Name:     "ubuntu",
				Codename: "focal",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "codename and version info",
			distro: DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				Codename:     "focal",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "conflicting codename and version info",
			distro: DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				Codename:     "fake",
			},
		},
		{
			name: "alpine edge version",
			distro: DistroSpecifier{
				Name:         "alpine",
				MajorVersion: "3",
				MinorVersion: "21",
				LabelVersion: "3.21.0_alpha20240807",
			},
			expected: []OperatingSystem{*alpineEdge},
		},
		{
			name: "arch rolling variant",
			distro: DistroSpecifier{
				Name: "arch",
			},
			expected: []OperatingSystem{*arch},
		},
		{
			name: "wolfi rolling variant",
			distro: DistroSpecifier{
				Name:         "wolfi",
				MajorVersion: "20221018",
			},
			expected: []OperatingSystem{*wolfi},
		},
		{
			name: "debian by codename for rolling alias",
			distro: DistroSpecifier{
				Name:         "debian",
				MajorVersion: "13",
				Codename:     "trixie", // TODO: what about sid status indication from pretty-name or /etc/debian_version?
			},
			expected: []OperatingSystem{*debianTrixie},
		},
		{
			name: "debian by codename",
			distro: DistroSpecifier{
				Name:     "debian",
				Codename: "wheezy",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "debian by major version",
			distro: DistroSpecifier{
				Name:         "debian",
				MajorVersion: "7",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "debian by major.minor version",
			distro: DistroSpecifier{
				Name:         "debian",
				MajorVersion: "7",
				MinorVersion: "2",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "alpine with major and minor version",
			distro: DistroSpecifier{
				Name:         "alpine",
				MajorVersion: "3",
				MinorVersion: "18",
			},
			expected: []OperatingSystem{*alpine318},
		},
		{
			name: "missing distro name",
			distro: DistroSpecifier{
				MajorVersion: "8",
			},
			expectErr: expectErrIs(t, ErrMissingDistroIdentification),
		},
		{
			name: "nonexistent distro",
			distro: DistroSpecifier{
				Name:         "madeup",
				MajorVersion: "99",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectErr == nil {
				tt.expectErr = require.NoError
			}
			result, err := s.resolveDistro(tt.distro)
			tt.expectErr(t, err)
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.expected, result, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDistroDisplay(t *testing.T) {
	tests := []struct {
		name     string
		distro   *DistroSpecifier
		expected string
	}{
		{
			name:     "nil distro",
			distro:   AnyDistroSpecified,
			expected: "any",
		},
		{
			name:     "no distro specified",
			distro:   NoDistroSpecified,
			expected: "none",
		},
		{
			name: "only name specified",
			distro: &DistroSpecifier{
				Name: "ubuntu",
			},
			expected: "ubuntu",
		},
		{
			name: "name and major version specified",
			distro: &DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
			},
			expected: "ubuntu@20",
		},
		{
			name: "name, major, and minor version specified",
			distro: &DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			expected: "ubuntu@20.04",
		},
		{
			name: "name, major version, and codename specified",
			distro: &DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				Codename:     "focal",
			},
			expected: "ubuntu@20 (focal)",
		},
		{
			name: "name and codename specified",
			distro: &DistroSpecifier{
				Name:     "ubuntu",
				Codename: "focal",
			},
			expected: "ubuntu@focal",
		},
		{
			name: "name, major version, minor version, and codename specified",
			distro: &DistroSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				Codename:     "focal",
			},
			expected: "ubuntu@20.04",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := distroDisplay(tt.distro)
			require.Equal(t, tt.expected, result)
		})
	}
}

func testDistro1AffectedPackage2Handle() *AffectedPackageHandle {
	now := time.Date(2023, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2d",
		},
		Vulnerability: &VulnerabilityHandle{
			Name:          "CVE-2023-1234",
			Status:        string(VulnerabilityRejected),
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
			Codename:     "focal",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}
}

func testDistro2AffectedPackage2Handle() *AffectedPackageHandle {
	now := time.Date(2020, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2d",
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
			Codename:     "groovy",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}

func testNonDistroAffectedPackage2Handle() *AffectedPackageHandle {
	now := time.Date(2005, 1, 1, 3, 4, 5, 0, time.UTC)
	later := now.Add(time.Hour * 200)
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2",
		},
		Vulnerability: &VulnerabilityHandle{
			Name:          "CVE-2023-4567",
			PublishedDate: &now,
			ModifiedDate:  &later,
			Provider: &Provider{
				ID: "wolfi",
			},
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}

func expectErrIs(t *testing.T, expected error) require.ErrorAssertionFunc {
	t.Helper()
	return func(t require.TestingT, err error, msgAndArgs ...interface{}) {
		require.Error(t, err, msgAndArgs...)
		assert.ErrorIs(t, err, expected)
	}
}

func strRef(s string) *string {
	return &s
}

func idRef(i int64) *ID {
	v := ID(i)
	return &v
}

func pkgFromName(name string) *PackageSpecifier {
	return &PackageSpecifier{Name: name}
}
