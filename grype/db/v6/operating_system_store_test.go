package v6

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/version"
)

func TestOperatingSystemStore_ResolveOperatingSystem(t *testing.T) {
	// we always preload the OS aliases into the DB when staging for writing
	db := setupTestStore(t).db
	bs := newBlobStore(db)
	oss := newOperatingSystemStore(db, bs)

	ubuntu2004 := &OperatingSystem{Name: "ubuntu", ReleaseID: "ubuntu", MajorVersion: "20", MinorVersion: "04", LabelVersion: "focal"}
	ubuntu2010 := &OperatingSystem{Name: "ubuntu", MajorVersion: "20", MinorVersion: "10", LabelVersion: "groovy"}
	rhel8 := &OperatingSystem{Name: "rhel", ReleaseID: "rhel", MajorVersion: "8"}
	rhel81 := &OperatingSystem{Name: "rhel", ReleaseID: "rhel", MajorVersion: "8", MinorVersion: "1"}
	debian10 := &OperatingSystem{Name: "debian", ReleaseID: "debian", MajorVersion: "10"}
	debian13 := &OperatingSystem{Name: "debian", ReleaseID: "debian", MajorVersion: "13", Codename: "trixie"}
	echo := &OperatingSystem{Name: "echo", ReleaseID: "echo", MajorVersion: "1"}
	alpine318 := &OperatingSystem{Name: "alpine", ReleaseID: "alpine", MajorVersion: "3", MinorVersion: "18"}
	alpineEdge := &OperatingSystem{Name: "alpine", ReleaseID: "alpine", LabelVersion: "edge"}
	debianUnstable := &OperatingSystem{Name: "debian", ReleaseID: "debian", LabelVersion: "unstable"}
	debian7 := &OperatingSystem{Name: "debian", ReleaseID: "debian", MajorVersion: "7", LabelVersion: "wheezy"}
	wolfi := &OperatingSystem{Name: "wolfi", ReleaseID: "wolfi", MajorVersion: "20230201"}
	arch := &OperatingSystem{Name: "archlinux", ReleaseID: "arch", MajorVersion: "20241110", MinorVersion: "0"}
	oracle5 := &OperatingSystem{Name: "oracle", ReleaseID: "ol", MajorVersion: "5"}
	oracle6 := &OperatingSystem{Name: "oracle", ReleaseID: "ol", MajorVersion: "6"}
	amazon2 := &OperatingSystem{Name: "amazon", ReleaseID: "amzn", MajorVersion: "2"}
	minimos := &OperatingSystem{Name: "minimos", ReleaseID: "minimos", MajorVersion: "20241031"}
	rocky8 := &OperatingSystem{Name: "rocky", ReleaseID: "rocky", MajorVersion: "8"}        // should not be matched
	alma8 := &OperatingSystem{Name: "almalinux", ReleaseID: "almalinux", MajorVersion: "8"} // should not be matched

	operatingSystems := []*OperatingSystem{
		ubuntu2004,
		ubuntu2010,
		rhel8,
		rhel81,
		debian10,
		debian13,
		alpine318,
		alpineEdge,
		debianUnstable,
		debian7,
		wolfi,
		arch,
		oracle5,
		oracle6,
		amazon2,
		minimos,
		rocky8,
		alma8,
		echo,
	}
	require.NoError(t, db.Create(&operatingSystems).Error)

	tests := []struct {
		name      string
		os        OSSpecifier
		expected  []OperatingSystem
		expectErr require.ErrorAssertionFunc
	}{
		{
			name: "specific distro with major and minor version",
			os: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "specific distro with major and minor version (missing left padding)",
			os: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "4",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "alias resolution with major version",
			os: OSSpecifier{
				Name:         "centos",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "alias resolution with major and minor version",
			os: OSSpecifier{
				Name:         "centos",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			expected: []OperatingSystem{*rhel81},
		},
		{
			name: "distro with major version only",
			os: OSSpecifier{
				Name:         "debian",
				MajorVersion: "10",
			},
			expected: []OperatingSystem{*debian10},
		},
		{
			name: "codename resolution",
			os: OSSpecifier{
				Name:         "ubuntu",
				LabelVersion: "focal",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "codename and version info",
			os: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			expected: []OperatingSystem{*ubuntu2004},
		},
		{
			name: "conflicting codename and version info",
			os: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "fake",
			},
		},
		{
			name: "alpine edge version",
			os: OSSpecifier{
				Name:         "alpine",
				MajorVersion: "3",
				MinorVersion: "21",
				LabelVersion: "3.21.0_alpha20240807",
			},
			expected: []OperatingSystem{*alpineEdge},
		},
		{
			name: "arch rolling variant",
			os: OSSpecifier{
				Name: "arch",
			},
			expected: []OperatingSystem{*arch},
		},
		{
			name: "wolfi rolling variant",
			os: OSSpecifier{
				Name:         "wolfi",
				MajorVersion: "20221018",
			},
			expected: []OperatingSystem{*wolfi},
		},
		{
			name: "debian by codename for rolling alias",
			os: OSSpecifier{
				Name:         "debian",
				MajorVersion: "13",
				LabelVersion: "trixie",
			},
			expected: []OperatingSystem{*debian13},
		},
		{
			name: "debian by codename for rolling alias",
			os: OSSpecifier{
				Name:         "debian",
				MajorVersion: "14",
				LabelVersion: "forky",
			},
			expected: []OperatingSystem{*debianUnstable},
		},
		{
			name: "debian by codename",
			os: OSSpecifier{
				Name:         "debian",
				LabelVersion: "wheezy",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "debian by major version",
			os: OSSpecifier{
				Name:         "debian",
				MajorVersion: "7",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "debian by major.minor version",
			os: OSSpecifier{
				Name:         "debian",
				MajorVersion: "7",
				MinorVersion: "2",
			},
			expected: []OperatingSystem{*debian7},
		},
		{
			name: "alpine with major and minor version",
			os: OSSpecifier{
				Name:         "alpine",
				MajorVersion: "3",
				MinorVersion: "18",
			},
			expected: []OperatingSystem{*alpine318},
		},
		{
			name: "lookup by release ID (not name)",
			os: OSSpecifier{
				Name:         "ol",
				MajorVersion: "5",
			},
			expected: []OperatingSystem{*oracle5},
		},
		{
			name: "lookup by non-standard name (oraclelinux)",
			os: OSSpecifier{
				Name:         "oraclelinux", // based on the grype distro names
				MajorVersion: "5",
			},
			expected: []OperatingSystem{*oracle5},
		},
		{
			name: "lookup by non-standard name (amazonlinux)",
			os: OSSpecifier{
				Name:         "amazonlinux", // based on the grype distro names
				MajorVersion: "2",
			},
			expected: []OperatingSystem{*amazon2},
		},
		{
			name: "lookup by non-standard name (oracle)",
			os: OSSpecifier{
				Name:         "oracle",
				MajorVersion: "5",
			},
			expected: []OperatingSystem{*oracle5},
		},
		{
			name: "lookup by non-standard name (amazon)",
			os: OSSpecifier{
				Name:         "amazon",
				MajorVersion: "2",
			},
			expected: []OperatingSystem{*amazon2},
		},
		{
			name: "lookup by non-standard name (rocky)",
			os: OSSpecifier{
				Name:         "rocky",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "lookup by non-standard name (rockylinux)",
			os: OSSpecifier{
				Name:         "rockylinux",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "lookup by non-standard name (alma)",
			os: OSSpecifier{
				Name:         "alma",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "lookup by non-standard name (almalinux)",
			os: OSSpecifier{
				Name:         "almalinux",
				MajorVersion: "8",
			},
			expected: []OperatingSystem{*rhel8},
		},
		{
			name: "echo rolling variant",
			os: OSSpecifier{
				Name:         "echo",
				MajorVersion: "1",
			},
			expected: []OperatingSystem{*echo},
		},
		{
			name: "missing distro name",
			os: OSSpecifier{
				MajorVersion: "8",
			},
			expectErr: expectErrIs(t, ErrMissingOSIdentification),
		},
		{
			name: "nonexistent distro",
			os: OSSpecifier{
				Name:         "madeup",
				MajorVersion: "99",
			},
		},
		{
			name: "minimos rolling variant",
			os: OSSpecifier{
				Name: "minimos",
			},
			expected: []OperatingSystem{*minimos},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectErr == nil {
				tt.expectErr = require.NoError
			}
			result, err := oss.GetOperatingSystems(tt.os)
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

func TestOSSpecifier_String(t *testing.T) {
	tests := []struct {
		name     string
		os       *OSSpecifier
		expected string
	}{
		{
			name:     "nil distro",
			os:       AnyOSSpecified,
			expected: "any",
		},
		{
			name:     "no distro specified",
			os:       NoOSSpecified,
			expected: "none",
		},
		{
			name: "only name specified",
			os: &OSSpecifier{
				Name: "ubuntu",
			},
			expected: "ubuntu",
		},
		{
			name: "name and major version specified",
			os: &OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
			},
			expected: "ubuntu@20",
		},
		{
			name: "name, major, and minor version specified",
			os: &OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			expected: "ubuntu@20.04",
		},
		{
			name: "name, major version, and codename specified",
			os: &OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				LabelVersion: "focal",
			},
			expected: "ubuntu@20 (focal)",
		},
		{
			name: "name and codename specified",
			os: &OSSpecifier{
				Name:         "ubuntu",
				LabelVersion: "focal",
			},
			expected: "ubuntu@focal",
		},
		{
			name: "name, major version, minor version, and codename specified",
			os: &OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			expected: "ubuntu@20.04",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.os.String()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestTrimZeroes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single zero",
			input:    "0",
			expected: "0",
		},
		{
			name:     "multiple zeros only",
			input:    "000",
			expected: "0",
		},
		{
			name:     "single non-zero digit",
			input:    "5",
			expected: "5",
		},
		{
			name:     "no leading zeros",
			input:    "123",
			expected: "123",
		},
		{
			name:     "single leading zero",
			input:    "0123",
			expected: "123",
		},
		{
			name:     "multiple leading zeros",
			input:    "000123",
			expected: "123",
		},
		{
			name:     "leading zeros with trailing zeros",
			input:    "001230",
			expected: "1230",
		},
		{
			name:     "string starting with non-zero",
			input:    "1000",
			expected: "1000",
		},
		{
			name:     "mixed digits with leading zeros",
			input:    "00042",
			expected: "42",
		},
		{
			name:     "very long leading zeros",
			input:    "00000000001",
			expected: "1",
		},
		{
			name:     "alphanumeric with leading zero",
			input:    "0abc",
			expected: "abc",
		},
		{
			name:     "special characters with leading zeros",
			input:    "00.123",
			expected: ".123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimZeroes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOSSpecifier_clean(t *testing.T) {
	tests := []struct {
		name  string
		input OSSpecifier
		want  OSSpecifier
	}{
		{
			name: "trim 0s",
			input: OSSpecifier{
				Name:         "Ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			want: OSSpecifier{
				Name:         "Ubuntu",
				MajorVersion: "20",
				MinorVersion: "4",
			},
		},
		{
			name: "preserve 0 value",
			input: OSSpecifier{
				Name:         "Redhat",
				MajorVersion: "9",
				MinorVersion: "0",
			},
			want: OSSpecifier{
				Name:         "Redhat",
				MajorVersion: "9",
				MinorVersion: "0", // important! ...9 != 9.0 since 9 includes multiple minor versions
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := tt.input
			o.clean()
			if d := cmp.Diff(tt.want, o); d != "" {
				t.Errorf("OSSpecifier.clean() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestApplyOverride(t *testing.T) {
	tests := []struct {
		name        string
		osSpecifier OSSpecifier
		override    OperatingSystemSpecifierOverride
		expected    OSSpecifier
		wantApplied bool
	}{
		{
			name: "replace name",
			osSpecifier: OSSpecifier{
				Name:         "centos",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementName: strPtr("rhel"),
			},
			expected: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			wantApplied: true,
		},
		{
			name: "replace major version",
			osSpecifier: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementMajorVersion: strPtr("9"),
			},
			expected: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "9",
				MinorVersion: "1",
			},
			wantApplied: true,
		},
		{
			name: "replace minor version",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementMinorVersion: strPtr("10"),
			},
			expected: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "10",
			},
			wantApplied: true,
		},
		{
			name: "replace label version",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementLabelVersion: strPtr("jammy"),
			},
			expected: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "jammy",
			},
			wantApplied: true,
		},
		{
			name: "replace channel",
			osSpecifier: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "9",
				MinorVersion: "1",
				Channel:      "eeus",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementChannel: strPtr("eus"),
			},
			expected: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "9",
				MinorVersion: "1",
				Channel:      "eus",
			},
			wantApplied: true,
		},
		{
			name: "rolling flag clears versions",
			osSpecifier: OSSpecifier{
				Name:         "arch",
				MajorVersion: "2024",
				MinorVersion: "01",
				LabelVersion: "rolling",
			},
			override: OperatingSystemSpecifierOverride{
				Rolling: true,
			},
			expected: OSSpecifier{
				Name:         "arch",
				MajorVersion: "",
				MinorVersion: "",
				LabelVersion: "rolling",
			},
			wantApplied: true,
		},
		{
			name: "comprehensive override - all fields",
			osSpecifier: OSSpecifier{
				Name:         "centos",
				MajorVersion: "7",
				MinorVersion: "5",
				LabelVersion: "core",
			},
			override: OperatingSystemSpecifierOverride{
				ReplacementName:         strPtr("rhel"),
				ReplacementMajorVersion: strPtr("7"),
				ReplacementMinorVersion: strPtr("9"),
				ReplacementLabelVersion: strPtr("server"),
			},
			expected: OSSpecifier{
				Name:         "rhel",
				MajorVersion: "7",
				MinorVersion: "9",
				LabelVersion: "server",
			},
			wantApplied: true,
		},
		{
			name: "no replacement fields - no changes",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			override: OperatingSystemSpecifierOverride{
				Alias: "ubuntu",
			},
			expected: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			wantApplied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// make a copy to avoid modifying the original
			d := tt.osSpecifier
			applied := applyOverride(&d, tt.override)

			require.Equal(t, tt.wantApplied, applied)

			if diff := cmp.Diff(tt.expected, d); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestApplyOSSpecifierOverrides(t *testing.T) {
	tests := []struct {
		name          string
		osSpecifier   OSSpecifier
		aliases       []OperatingSystemSpecifierOverride
		clientVersion *version.Version
		wantErr       require.ErrorAssertionFunc
		expected      OSSpecifier
	}{
		{
			name: "no aliases - no change",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			aliases: []OperatingSystemSpecifierOverride{},
			expected: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
		},
		{
			name: "multiple overrides - first match wins",
			osSpecifier: OSSpecifier{
				Name:         "centos",
				MajorVersion: "8",
				MinorVersion: "1",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:           "centos",
					ReplacementName: strPtr("rhel"),
				},
				{
					Alias:           "centos",
					ReplacementName: strPtr("fedora"),
				},
			},
			expected: OSSpecifier{
				Name:         "rhel", // overridden
				MajorVersion: "8",
				MinorVersion: "1",
			},
		},
		{
			name: "codename mismatch - no override",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:           "ubuntu",
					Codename:        "jammy",
					ReplacementName: strPtr("ubuntu-lts"),
				},
			},
			expected: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
				LabelVersion: "focal", // not overridden
			},
		},
		{
			name: "version mismatch - no override",
			osSpecifier: OSSpecifier{
				Name:         "debian",
				MajorVersion: "10",
				MinorVersion: "5",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:           "debian",
					Version:         "11.0",
					ReplacementName: strPtr("debian-bullseye"),
				},
			},
			expected: OSSpecifier{
				Name:         "debian",
				MajorVersion: "10", // not overridden
				MinorVersion: "5",  // not overridden
			},
		},
		{
			name: "version pattern mismatch - no override",
			osSpecifier: OSSpecifier{
				Name:         "alpine",
				MajorVersion: "2",
				MinorVersion: "18",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:           "alpine",
					VersionPattern:  "^3\\.[0-9]+$",
					ReplacementName: strPtr("alpine-stable"),
				},
			},
			expected: OSSpecifier{
				Name:         "alpine", // not overridden
				MajorVersion: "2",
				MinorVersion: "18",
			},
		},
		{
			name: "client version constraint satisfied",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:                     "ubuntu",
					ApplicableClientDBSchemas: ">=1.0.0",
					ReplacementName:           strPtr("ubuntu-new"),
				},
			},
			clientVersion: version.New("1.2.0", version.SemanticFormat), // matches the constraint, thus allowed to override
			expected: OSSpecifier{
				Name:         "ubuntu-new", // overridden
				MajorVersion: "20",
				MinorVersion: "04",
			},
		},
		{
			name: "client version constraint not satisfied",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:                     "ubuntu",
					ApplicableClientDBSchemas: ">=2.0.0", // does not match the client version, thus no override
					ReplacementName:           strPtr("ubuntu-new"),
				},
			},
			clientVersion: version.New("1.2.0", version.SemanticFormat),
			expected: OSSpecifier{
				Name:         "ubuntu", // not overridden
				MajorVersion: "20",
				MinorVersion: "04",
			},
		},
		{
			name: "invalid client version constraint - honor the override",
			osSpecifier: OSSpecifier{
				Name:         "ubuntu",
				MajorVersion: "20",
				MinorVersion: "04",
			},
			aliases: []OperatingSystemSpecifierOverride{
				{
					Alias:                     "ubuntu",
					ApplicableClientDBSchemas: "invalid-constraint", // oops!
					ReplacementName:           strPtr("ubuntu-new"),
				},
			},
			clientVersion: version.New("1.2.0", version.SemanticFormat),
			expected: OSSpecifier{
				Name:         "ubuntu-new", // overridden
				MajorVersion: "20",
				MinorVersion: "04",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			// make a copy to avoid modifying the original
			d := tt.osSpecifier
			err := applyOSSpecifierOverrides(&d, tt.aliases, tt.clientVersion)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.expected, d); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
