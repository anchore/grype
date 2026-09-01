package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetails_SearchedPackageVersion(t *testing.T) {
	tests := []struct {
		name    string
		details Details
		want    string
		wantOK  bool
	}{
		{
			name:    "distro details name the version their search was made at",
			details: Details{{SearchedBy: DistroParameters{Package: PackageParameter{Name: "openssl", Version: "1.1.1"}}}},
			want:    "1.1.1",
			wantOK:  true,
		},
		{
			name:    "ecosystem details do too",
			details: Details{{SearchedBy: EcosystemParameters{Package: PackageParameter{Name: "django", Version: "3.2"}}}},
			want:    "3.2",
			wantOK:  true,
		},
		{
			name:    "cpe details do not: their package version is the cataloged one, not what the search compared against",
			details: Details{{SearchedBy: CPEParameters{Package: PackageParameter{Name: "openssl", Version: "1.1.1-r2"}}}},
			wantOK:  false,
		},
		{
			name:    "a blank version is no version",
			details: Details{{SearchedBy: DistroParameters{Package: PackageParameter{Name: "openssl"}}}},
			wantOK:  false,
		},
		{
			name: "the first detail to name one answers for the set",
			details: Details{
				{SearchedBy: CPEParameters{Package: PackageParameter{Version: "cataloged"}}},
				{SearchedBy: DistroParameters{Package: PackageParameter{Version: "searched"}}},
			},
			want:   "searched",
			wantOK: true,
		},
		{
			name:   "no details, no version",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.details.SearchedPackageVersion()
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
