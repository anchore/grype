package unmarshal

import "io"

// EndOfLifeDateRelease represents a single release entry from the endoflife.date API v1.
// This matches the ProductRelease schema with camelCase field names.
// Ref: https://endoflife.date/api/v1/products/{product}
//
// Note: Product and Identifiers are denormalized from the parent product by vunnel.
type EndOfLifeDateRelease struct {
	// Denormalized fields added by vunnel
	Product     string                    `json:"product"`
	Identifiers []EndOfLifeDateIdentifier `json:"identifiers"`

	// Fields from endoflife.date ProductRelease schema
	Name         string                 `json:"name"`
	Codename     *string                `json:"codename"`
	Label        string                 `json:"label"`
	ReleaseDate  *string                `json:"releaseDate"`
	IsLTS        bool                   `json:"isLts"`
	LTSFrom      *string                `json:"ltsFrom"`
	IsEOAS       bool                   `json:"isEoas"`
	EOASFrom     *string                `json:"eoasFrom"`
	IsEOL        bool                   `json:"isEol"`
	EOLFrom      *string                `json:"eolFrom"`
	IsMaintained bool                   `json:"isMaintained"`
	Latest       *EndOfLifeDateLatest   `json:"latest"`
	Custom       map[string]interface{} `json:"custom"`
}

// EndOfLifeDateLatest represents the latest release info nested within a release.
type EndOfLifeDateLatest struct {
	Name string  `json:"name"`
	Date *string `json:"date"`
	Link *string `json:"link"`
}

// EndOfLifeDateIdentifier represents a CPE, PURL, or Repology identifier.
type EndOfLifeDateIdentifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EndOfLifeDateLabels contains custom labels for EOL-related dates.
type EndOfLifeDateLabels struct {
	EOAS         *string `json:"eoas"`
	Discontinued *string `json:"discontinued"`
	EOL          *string `json:"eol"`
	EOES         *string `json:"eoes"`
}

// EndOfLifeDateLinks contains URLs for the product.
type EndOfLifeDateLinks struct {
	Icon          *string `json:"icon"`
	HTML          *string `json:"html"`
	ReleasePolicy *string `json:"releasePolicy"`
}

// EndOfLifeDateResult represents the result object within a product response.
type EndOfLifeDateResult struct {
	Name           string                    `json:"name"`
	Aliases        []string                  `json:"aliases"`
	Label          string                    `json:"label"`
	Category       string                    `json:"category"`
	Tags           []string                  `json:"tags"`
	VersionCommand *string                   `json:"versionCommand"`
	Identifiers    []EndOfLifeDateIdentifier `json:"identifiers"`
	Labels         EndOfLifeDateLabels       `json:"labels"`
	Links          EndOfLifeDateLinks        `json:"links"`
	Releases       []EndOfLifeDateRelease    `json:"releases"`
}

// EndOfLifeDateProduct represents the full product response from the endoflife.date API v1.
type EndOfLifeDateProduct struct {
	SchemaVersion string              `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	LastModified  string              `json:"last_modified"`
	Result        EndOfLifeDateResult `json:"result"`
}

// IsEmpty returns true if the release has no meaningful data.
func (e EndOfLifeDateRelease) IsEmpty() bool {
	return e.Product == ""
}

// ProductName returns the product name from the release.
func (e EndOfLifeDateRelease) ProductName() string {
	return e.Product
}

// EndOfLifeDateReleaseEntries unmarshals EndOfLifeDateRelease records from a reader.
func EndOfLifeDateReleaseEntries(reader io.Reader) ([]EndOfLifeDateRelease, error) {
	return unmarshalSingleOrMulti[EndOfLifeDateRelease](reader)
}
