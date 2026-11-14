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
	CNA CVE5CNAContainer   `json:"cna"`
	Adp []CVE5ADPContainer `json:"adp"`
}

// AnchoreADPShortName is the `providerMetadata.shortName` of the ADP container that restates the CNA's affected
// products with package URLs and structured ranges.
const AnchoreADPShortName = "anchoreadp"

// CVE5ADPContainer decodes the parts of an ADP container that reconciliation reads, in the CNA's types. Other
// ADP containers (CISA-ADP, CVE) decode with empty lists.
type CVE5ADPContainer struct {
	ProviderMetadata CVE5ProviderMetadata `json:"providerMetadata"`
	Affected         []CVE5Affected       `json:"affected"`
	CPEApplicability []nvd.Configuration  `json:"cpeApplicability"`
}

type CVE5ProviderMetadata struct {
	ShortName string `json:"shortName"`
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

// AnchoreADP returns the first ADP container named `anchoreadp`, or nil. Its array index differs between records.
func (r CVE5Record) AnchoreADP() *CVE5ADPContainer {
	for i := range r.Containers.Adp {
		if r.Containers.Adp[i].ProviderMetadata.ShortName == AnchoreADPShortName {
			return &r.Containers.Adp[i]
		}
	}
	return nil
}

func CVE5Entries(reader io.Reader) ([]CVE5Record, error) {
	return unmarshalSingleOrMulti[CVE5Record](reader)
}
