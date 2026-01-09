package distro

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/linux"
)

func TestTypeFromRelease(t *testing.T) {

	tests := []struct {
		name    string
		release linux.Release
		want    Type
	}{
		{
			name: "direct ID mapping",
			release: linux.Release{
				ID: "ubuntu",
			},
			want: Ubuntu,
		},
		{
			name: "direct ID mapping rhel",
			release: linux.Release{
				ID: "rhel",
			},
			want: RedHat,
		},
		{
			name: "alias mapping",
			release: linux.Release{
				ID: "Alpine Linux",
			},
			want: Alpine,
		},
		{
			name: "alias mapping windows",
			release: linux.Release{
				ID: "windows",
			},
			want: Windows,
		},
		{
			name: "ID_LIKE mapping",
			release: linux.Release{
				ID:     "unknown-distro",
				IDLike: []string{"debian", "ubuntu"},
			},
			want: Debian,
		},
		{
			name: "ID_LIKE alias mapping",
			release: linux.Release{
				ID:     "custom-alpine",
				IDLike: []string{"Alpine Linux"},
			},
			want: Alpine,
		},
		{
			name: "fallback to name ID mapping",
			release: linux.Release{
				ID:   "unrecognized",
				Name: "fedora",
			},
			want: Fedora,
		},
		{
			name: "fallback to name alias mapping",
			release: linux.Release{
				ID:   "unrecognized",
				Name: "windows",
			},
			want: Windows,
		},
		{
			name: "empty result when no matches",
			release: linux.Release{
				ID:   "totally-unknown",
				Name: "also-unknown",
			},
			want: "",
		},
		{
			name: "prefer ID over ID_LIKE",
			release: linux.Release{
				ID:     "ubuntu",
				IDLike: []string{"debian"},
			},
			want: Ubuntu,
		},
		{
			name: "prefer ID over name",
			release: linux.Release{
				ID:   "ubuntu",
				Name: "fedora",
			},
			want: Ubuntu,
		},
		{
			name: "prefer ID_LIKE over name",
			release: linux.Release{
				ID:     "unknown",
				IDLike: []string{"centos"},
				Name:   "fedora",
			},
			want: CentOS,
		},
		{
			name: "multiple ID_LIKE entries use first match",
			release: linux.Release{
				ID:     "unknown",
				IDLike: []string{"nonexistent", "alpine", "debian"},
			},
			want: Alpine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TypeFromRelease(tt.release)
			assert.Equal(t, tt.want, got)
		})
	}
}
