package distro

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// BellSoftHardenedContainers is the first hyphenated distro ID without a
// ParseDistroString special case (cf. opensuse-leap); this pins the behavior
// of string-form distro entry points (--distro hint, db search --os, purl
// distro qualifiers) for the new IDs.
func TestParseDistroString_BellSoft(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{input: "alpaquita:stream", wantName: "alpaquita", wantVersion: "stream"},
		{input: "alpaquita:23", wantName: "alpaquita", wantVersion: "23"},
		{input: "bellsoft-hardened-containers:stream", wantName: "bellsoft-hardened-containers", wantVersion: "stream"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := ParseDistroString(tt.input)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
			d := NewFromNameVersion(name, version)
			assert.Equal(t, tt.wantName, string(d.Type), "distro type should resolve to a known type")
		})
	}
}
