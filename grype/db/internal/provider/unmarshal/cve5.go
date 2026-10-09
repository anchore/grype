package unmarshal

import (
	"io"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
)

// decodes the parts of a CVE JSON 5 record that CNA reconciliation reads. The `cve5` provider writes
// cvelistV5 records unchanged, so this is that shape minus everything unused.
type CVE5Record struct {
	CVEMetadata CVE5Metadata   `json:"cveMetadata"`
	Containers  CVE5Containers `json:"containers"`
}

type CVE5Metadata struct {
	CVEID             string `json:"cveId"`
	State             string `json:"state"`
	AssignerShortName string `json:"assignerShortName"`
	DatePublished     string `json:"datePublished"`
	DateUpdated       string `json:"dateUpdated"`
}

type CVE5Containers struct {
	CNA CVE5CNAContainer `json:"cna"`
}

type CVE5CNAContainer struct {
	Descriptions []CVE5Description `json:"descriptions"`
	References   []CVE5Reference   `json:"references"`
	Affected     []CVE5Affected    `json:"affected"`

	// cpeApplicability shares NVD's configuration shape. CVE 5 omits matchCriteriaId, which decodes as empty.
	CPEApplicability []nvd.Configuration `json:"cpeApplicability"`
}

type CVE5Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CVE5Reference struct {
	URL string `json:"url"`
}

type CVE5Affected struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	PackageURL    string `json:"packageURL"`
	CollectionURL string `json:"collectionURL"`
	PackageName   string `json:"packageName"`
	DefaultStatus string `json:"defaultStatus"`

	Versions []CVE5Version `json:"versions"`
}

type CVE5Version struct {
	Version         string       `json:"version"`
	LessThan        string       `json:"lessThan"`
	LessThanOrEqual string       `json:"lessThanOrEqual"`
	Status          string       `json:"status"`
	VersionType     string       `json:"versionType"`
	Changes         []CVE5Change `json:"changes"`
}

type CVE5Change struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

func (r CVE5Record) IsEmpty() bool {
	return r.CVEMetadata.CVEID == ""
}

func CVE5Entries(reader io.Reader) ([]CVE5Record, error) {
	return unmarshalSingleOrMulti[CVE5Record](reader)
}
