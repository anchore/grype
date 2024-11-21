package v6

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAffectedPackageStore_AddAffectedPackages(t *testing.T) {
	db := setupTestStore(t).db
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
	db := setupTestStore(t).db
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
		wantErr     require.ErrorAssertionFunc
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
			name:        "distro major version only (allow multiple)",
			packageName: pkg2d1.Package.Name,
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
			name:        "distro major version only (default)",
			packageName: pkg2d1.Package.Name,
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
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
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
