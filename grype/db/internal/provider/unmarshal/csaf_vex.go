package unmarshal

import "io"

// CSAFVEXAdvisory represents a CSAF 2.0 VEX advisory document. Only fields
// relevant to vulnerability-database ingestion are included; the full CSAF
// spec has many more optional fields that we intentionally omit.
type CSAFVEXAdvisory struct {
	Document        CSAFDocument        `json:"document"`
	ProductTree     CSAFProductTree     `json:"product_tree"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// ── document metadata ────────────────────────────────────────────────

type CSAFDocument struct {
	Category          string                 `json:"category"`
	CSAFVersion       string                 `json:"csaf_version"`
	Title             string                 `json:"title"`
	Lang              string                 `json:"lang,omitempty"`
	AggregateSeverity *CSAFAggregateSeverity `json:"aggregate_severity,omitempty"`
	Distribution      *CSAFDistribution      `json:"distribution,omitempty"`
	Notes             []CSAFNote             `json:"notes,omitempty"`
	Publisher         CSAFPublisher          `json:"publisher"`
	References        []CSAFReference        `json:"references,omitempty"`
	Tracking          CSAFTracking           `json:"tracking"`
}

type CSAFAggregateSeverity struct {
	Namespace string `json:"namespace,omitempty"`
	Text      string `json:"text"`
}

type CSAFDistribution struct {
	Text string   `json:"text,omitempty"`
	TLP  *CSAFTLP `json:"tlp,omitempty"`
}

type CSAFTLP struct {
	Label string `json:"label"`
	URL   string `json:"url,omitempty"`
}

type CSAFPublisher struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

type CSAFTracking struct {
	CurrentReleaseDate string         `json:"current_release_date"`
	Generator          *CSAFGenerator `json:"generator,omitempty"`
	ID                 string         `json:"id"`
	InitialReleaseDate string         `json:"initial_release_date"`
	RevisionHistory    []CSAFRevision `json:"revision_history,omitempty"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
}

type CSAFGenerator struct {
	Date   string               `json:"date,omitempty"`
	Engine *CSAFGeneratorEngine `json:"engine,omitempty"`
}

type CSAFGeneratorEngine struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type CSAFRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary,omitempty"`
}

type CSAFNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type CSAFReference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url"`
}

// ── product tree ─────────────────────────────────────────────────────

type CSAFProductTree struct {
	Branches      []CSAFBranch       `json:"branches,omitempty"`
	Relationships []CSAFRelationship `json:"relationships,omitempty"`
}

type CSAFBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []CSAFBranch `json:"branches,omitempty"`
	Product  *CSAFProduct `json:"product,omitempty"`
}

type CSAFProduct struct {
	Name                        string                           `json:"name"`
	ProductID                   string                           `json:"product_id"`
	ProductIdentificationHelper *CSAFProductIdentificationHelper `json:"product_identification_helper,omitempty"`
}

type CSAFProductIdentificationHelper struct {
	CPE  string `json:"cpe,omitempty"`
	PURL string `json:"purl,omitempty"`
}

type CSAFRelationship struct {
	Category                  string      `json:"category"`
	FullProductName           CSAFProduct `json:"full_product_name"`
	ProductReference          string      `json:"product_reference"`
	RelatesToProductReference string      `json:"relates_to_product_reference"`
}

// ── vulnerabilities ──────────────────────────────────────────────────

type CSAFVulnerability struct {
	CVE           string             `json:"cve"`
	CWE           *CSAFCWE           `json:"cwe,omitempty"`
	Title         string             `json:"title,omitempty"`
	DiscoveryDate string             `json:"discovery_date,omitempty"`
	ReleaseDate   string             `json:"release_date,omitempty"`
	Flags         []CSAFFlag         `json:"flags,omitempty"`
	IDs           []CSAFVulnID       `json:"ids,omitempty"`
	Notes         []CSAFNote         `json:"notes,omitempty"`
	ProductStatus *CSAFProductStatus `json:"product_status,omitempty"`
	References    []CSAFReference    `json:"references,omitempty"`
	Remediations  []CSAFRemediation  `json:"remediations,omitempty"`
	Scores        []CSAFScore        `json:"scores,omitempty"`
	Threats       []CSAFThreat       `json:"threats,omitempty"`
}

type CSAFCWE struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type CSAFProductStatus struct {
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type CSAFFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type CSAFVulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type CSAFRemediation struct {
	Category   string   `json:"category"`
	Date       string   `json:"date,omitempty"`
	Details    string   `json:"details,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
	URL        string   `json:"url,omitempty"`
}

type CSAFScore struct {
	CVSSV2   *CSAFCVSSV2 `json:"cvss_v2,omitempty"`
	CVSSV3   *CSAFCVSSV3 `json:"cvss_v3,omitempty"`
	Products []string    `json:"products,omitempty"`
}

type CSAFCVSSV2 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

type CSAFCVSSV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

type CSAFThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// ── unmarshal entry point ────────────────────────────────────────────

func CSAFVEXAdvisoryEntries(reader io.Reader) ([]CSAFVEXAdvisory, error) {
	return unmarshalSingleOrMulti[CSAFVEXAdvisory](reader)
}
