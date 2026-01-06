package codename

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupOSCodename(t *testing.T) {
	tests := []struct {
		Name             string
		OSName           string
		MajorVersion     string
		MinorVersion     string
		ExpectedCodename string
	}{
		{Name: "Ubuntu 20.04 exact", OSName: "ubuntu", MajorVersion: "20", MinorVersion: "04", ExpectedCodename: "focal"},
		{Name: "Ubuntu 20.4 exact", OSName: "ubuntu", MajorVersion: "20", MinorVersion: "4", ExpectedCodename: "focal"},
		{Name: "Ubuntu 0 (non existent) minor", OSName: "ubuntu", MajorVersion: "20", MinorVersion: "0", ExpectedCodename: ""},
		{Name: "Ubuntu empty minor", OSName: "ubuntu", MajorVersion: "10", MinorVersion: "", ExpectedCodename: ""},
		{Name: "Debian empty minor", OSName: "debian", MajorVersion: "10", MinorVersion: "", ExpectedCodename: "buster"},
		{Name: "Ubuntu leading zeros in major", OSName: "ubuntu", MajorVersion: "020", MinorVersion: "04", ExpectedCodename: "focal"},
		{Name: "Debian leading zeros in major", OSName: "debian", MajorVersion: "010", MinorVersion: "", ExpectedCodename: "buster"},
		{Name: "Debian bad minor", OSName: "debian", MajorVersion: "11", MinorVersion: "99", ExpectedCodename: "bullseye"},
		{Name: "Ubuntu bad minor", OSName: "ubuntu", MajorVersion: "22", MinorVersion: "99", ExpectedCodename: ""},
		{Name: "Ubuntu 6.10 exact (legacy)", OSName: "ubuntu", MajorVersion: "6", MinorVersion: "10", ExpectedCodename: "edgy"},
		{Name: "Ubuntu 6.6 exact (legacy)", OSName: "ubuntu", MajorVersion: "6", MinorVersion: "6", ExpectedCodename: "dapper"},
		{Name: "Debian 2.1 exact", OSName: "debian", MajorVersion: "2", MinorVersion: "1", ExpectedCodename: "slink"},
		{Name: "Debian 2 fallback to *", OSName: "debian", MajorVersion: "2", MinorVersion: "0", ExpectedCodename: "hamm"},
		{Name: "Invalid OS name", OSName: "nonexistentOS", MajorVersion: "10", MinorVersion: "04", ExpectedCodename: ""},
		{Name: "Invalid major version", OSName: "ubuntu", MajorVersion: "99", MinorVersion: "04", ExpectedCodename: ""},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			actualCodename := LookupOS(tt.OSName, tt.MajorVersion, tt.MinorVersion)
			assert.Equal(t, tt.ExpectedCodename, actualCodename)
		})
	}
}
