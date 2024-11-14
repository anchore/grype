package v6

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAffectedPackageStore_AddAffectedPackages(t *testing.T) {
	db := setupTestDB(t)
	bs := newBlobStore(db)
	s := newAffectedPackageStore(db, bs)

	pkg1 := &AffectedPackageHandle{
		Package: &Package{Name: "pkg1", Type: "type1"},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-1234"},
		},
	}

	pkg2 := testDistro1AffectedPackage2Handle()

	err := s.AddAffectedPackages(pkg1, pkg2)
	require.NoError(t, err)

	var result1 AffectedPackageHandle
	err = db.Where("package_id = ?", pkg1.PackageID).First(&result1).Error
	require.NoError(t, err)
	assert.Equal(t, pkg1.PackageID, result1.PackageID)
	assert.Equal(t, pkg1.BlobID, result1.BlobID)
	require.Nil(t, result1.BlobValue) // no preloading on fetch

	var result2 AffectedPackageHandle
	err = db.Where("package_id = ?", pkg2.PackageID).First(&result2).Error
	require.NoError(t, err)
	assert.Equal(t, pkg2.PackageID, result2.PackageID)
	assert.Equal(t, pkg2.BlobID, result2.BlobID)
	assert.Nil(t, result2.BlobValue)
}

func TestAffectedPackageStore_GetAffectedPackagesByName(t *testing.T) {
	db := setupTestDB(t)
	bs := newBlobStore(db)
	s := newAffectedPackageStore(db, bs)

	pkg2d1 := testDistro1AffectedPackage2Handle()
	pkg2d2 := testDistro2AffectedPackage2Handle()
	pkg2 := testNonDistroAffectedPackage2Handle()
	err := s.AddAffectedPackages(pkg2d1, pkg2, pkg2d2)
	require.NoError(t, err)

	tests := []struct {
		name        string
		packageName string
		options     *GetAffectedPackageOptions
		expected    []AffectedPackageHandle
	}{
		{
			name:        "specific distro",
			packageName: pkg2d1.Package.Name,
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
			name:        "distro major version",
			packageName: pkg2d1.Package.Name,
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:         "ubuntu",
					MajorVersion: "20",
				},
			},
			expected: []AffectedPackageHandle{*pkg2d1, *pkg2d2},
		},
		{
			name:        "distro codename",
			packageName: pkg2d1.Package.Name,
			options: &GetAffectedPackageOptions{
				Distro: &DistroSpecifier{
					Name:     "ubuntu",
					Codename: "groovy",
				},
			},
			expected: []AffectedPackageHandle{*pkg2d2},
		},
		{
			name:        "no distro",
			packageName: pkg2.Package.Name,
			options: &GetAffectedPackageOptions{
				Distro: NoDistroSpecified,
			},
			expected: []AffectedPackageHandle{*pkg2},
		},
		{
			name:        "any distro",
			packageName: pkg2d1.Package.Name,
			options: &GetAffectedPackageOptions{
				Distro: AnyDistroSpecified,
			},
			expected: []AffectedPackageHandle{*pkg2d1, *pkg2, *pkg2d2},
		},
		{
			name:        "package type",
			packageName: pkg2.Package.Name,
			options: &GetAffectedPackageOptions{
				PackageType: "type2",
			},
			expected: []AffectedPackageHandle{*pkg2},
		},
	}

	type preloadConfig struct {
		name             string
		PreloadOS        bool
		PreloadPackage   bool
		PreloadBlob      bool
		prepExpectations func(*testing.T, []AffectedPackageHandle) []AffectedPackageHandle
	}

	preloadCases := []preloadConfig{
		{
			name:           "preload-all",
			PreloadOS:      true,
			PreloadPackage: true,
			PreloadBlob:    true,
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				for _, a := range in {
					if a.OperatingSystemID != nil {
						require.NotNil(t, a.OperatingSystem)
					}
					require.NotNil(t, a.Package)
					require.NotNil(t, a.BlobValue)
				}
				return in
			},
		},
		{
			name: "preload-none",
			prepExpectations: func(t *testing.T, in []AffectedPackageHandle) []AffectedPackageHandle {
				var out []AffectedPackageHandle
				for _, v := range in {
					v.OperatingSystem = nil
					v.Package = nil
					v.BlobValue = nil
					out = append(out, v)
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
					a.Package = nil
					a.BlobValue = nil
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
					a.OperatingSystem = nil
					a.BlobValue = nil
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
					a.OperatingSystem = nil
					a.Package = nil
					out = append(out, a)
				}
				return out
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			for _, pc := range preloadCases {
				t.Run(pc.name, func(t *testing.T) {
					opts := tt.options
					opts.PreloadOS = pc.PreloadOS
					opts.PreloadPackage = pc.PreloadPackage
					opts.PreloadBlob = pc.PreloadBlob
					expected := tt.expected
					if pc.prepExpectations != nil {
						expected = pc.prepExpectations(t, expected)
					}
					result, err := s.GetAffectedPackagesByName(tt.packageName, opts)
					require.NoError(t, err)
					if d := cmp.Diff(expected, result); d != "" {
						t.Errorf(fmt.Sprintf("unexpected result: %s", d))
					}
				})
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
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2d",
		},
		OperatingSystem: &OperatingSystem{
			Name:         "ubuntu",
			MajorVersion: "20",
			MinorVersion: "04",
			Codename:     "focal",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}

func testDistro2AffectedPackage2Handle() *AffectedPackageHandle {
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2d",
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
	return &AffectedPackageHandle{
		Package: &Package{
			Name: "pkg2",
			Type: "type2",
		},
		BlobValue: &AffectedPackageBlob{
			CVEs: []string{"CVE-2023-4567"},
		},
	}
}
