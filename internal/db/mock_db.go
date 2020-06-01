package db

import (
	"github.com/anchore/vulnscan-db/pkg/db"
)

type MockDb struct {
	data map[string]map[string][]db.Vulnerability
}

func NewMockDb() *MockDb {
	d := MockDb{
		data: make(map[string]map[string][]db.Vulnerability),
	}
	d.populate()
	return &d
}

func (d *MockDb) populate() {
	d.data["debian:8"] = map[string][]db.Vulnerability{
		"neutron": {
			{
				Name:            "neutron",
				NamespaceName:   "debian:8",
				Version:         "2014.1.3-6",
				VulnerabilityID: "CVE-2014-fake",
				VersionFormat:   "dpkg",
			},
		},
	}
}

func (d *MockDb) Add(v *db.Vulnerability) error {
	return nil
}

func (d *MockDb) Get(namespace, name string) ([]db.Vulnerability, error) {
	return d.data[namespace][name], nil
}
