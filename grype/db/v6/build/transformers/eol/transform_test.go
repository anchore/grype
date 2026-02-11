package eol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		cycle     string
		wantMajor string
		wantMinor string
	}{
		{
			name:      "major only",
			cycle:     "12",
			wantMajor: "12",
			wantMinor: "",
		},
		{
			name:      "major and minor",
			cycle:     "22.04",
			wantMajor: "22",
			wantMinor: "4",
		},
		{
			name:      "major minor patch",
			cycle:     "8.5.1",
			wantMajor: "8",
			wantMinor: "5",
		},
		{
			name:      "leading zero in minor",
			cycle:     "20.04",
			wantMajor: "20",
			wantMinor: "4",
		},
		{
			name:      "leading zero in major",
			cycle:     "08",
			wantMajor: "8",
			wantMinor: "",
		},
		{
			name:      "non-numeric version",
			cycle:     "bullseye",
			wantMajor: "bullseye",
			wantMinor: "",
		},
		{
			name:      "mixed numeric and non-numeric",
			cycle:     "3.x",
			wantMajor: "3",
			wantMinor: "x",
		},
		{
			name:      "empty string",
			cycle:     "",
			wantMajor: "",
			wantMinor: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMajor, gotMinor := parseVersion(tt.cycle)
			assert.Equal(t, tt.wantMajor, gotMajor, "major version mismatch")
			assert.Equal(t, tt.wantMinor, gotMinor, "minor version mismatch")
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "no leading zeros",
			version: "12",
			want:    "12",
		},
		{
			name:    "single leading zero",
			version: "04",
			want:    "4",
		},
		{
			name:    "multiple leading zeros",
			version: "004",
			want:    "4",
		},
		{
			name:    "zero value",
			version: "0",
			want:    "0",
		},
		{
			name:    "non-numeric",
			version: "bullseye",
			want:    "bullseye",
		},
		{
			name:    "mixed content",
			version: "12a",
			want:    "12a",
		},
		{
			name:    "empty string",
			version: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeVersion(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTranslateProductName(t *testing.T) {
	tests := []struct {
		name    string
		product string
		want    string
	}{
		{
			name:    "alpine-linux to alpine",
			product: "alpine-linux",
			want:    "alpine",
		},
		{
			name:    "rhel to redhat",
			product: "rhel",
			want:    "redhat",
		},
		{
			name:    "amazon-linux to amazonlinux",
			product: "amazon-linux",
			want:    "amazonlinux",
		},
		{
			name:    "oracle-linux to oraclelinux",
			product: "oracle-linux",
			want:    "oraclelinux",
		},
		{
			name:    "rocky-linux to rockylinux",
			product: "rocky-linux",
			want:    "rockylinux",
		},
		{
			name:    "centos-stream to centos",
			product: "centos-stream",
			want:    "centos",
		},
		{
			name:    "unmapped product returns as-is",
			product: "debian",
			want:    "debian",
		},
		{
			name:    "ubuntu returns as-is",
			product: "ubuntu",
			want:    "ubuntu",
		},
		{
			name:    "unknown product returns as-is",
			product: "some-unknown-product",
			want:    "some-unknown-product",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateProductName(tt.product)
			assert.Equal(t, tt.want, got)
		})
	}
}
