package lightwell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseVersion(t *testing.T) {
	tests := []struct {
		version  string
		wantBase string
		wantOK   bool
	}{
		{version: "6.0.3.rhlw-00001", wantBase: "6.0.3", wantOK: true},
		{version: "4.1.100.Final-rhlw-00001", wantBase: "4.1.100.Final", wantOK: true},
		{version: "3.0.15.RELEASE-rhlw-00009", wantBase: "3.0.15.RELEASE", wantOK: true},
		{version: "3.0.1+rhlw.1", wantBase: "3.0.1", wantOK: true},
		{version: "6.0.3.RHLW-00001", wantBase: "6.0.3", wantOK: true},
		{version: "6.0.3"},
		{version: "6.0.3-rhlw"},
		{version: "6.0.3.rhlw-00001-SNAPSHOT"},
		{version: ".rhlw-00001"},
		{version: ""},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			base, ok := BaseVersion(tt.version)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantBase, base)
		})
	}
}
