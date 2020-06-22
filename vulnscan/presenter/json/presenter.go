package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/result"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct{}

// NewPresenter is a *Presenter constructor
func NewPresenter() *Presenter {
	return &Presenter{}
}

// ResultObj is a single item for the JSON array reported
type ResultObj struct {
	Cve     string  `json:"cve"`
	Package Package `json:"package"`
}

// Package is a nested JSON object from ResultObj
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer, catalog *pkg.Catalog, results result.Result) error {
	doc := make([]ResultObj, 0)

	for match := range results.Enumerate() {
		pkg := catalog.Package(match.Package.ID())
		doc = append(
			doc,
			ResultObj{
				Cve:     match.Vulnerability.ID,
				Package: Package{Name: pkg.Name, Version: pkg.Version}},
		)

		doc = append(
			doc,
			ResultObj{
				Cve:     match.Vulnerability.ID,
				Package: Package{Name: pkg.Name, Version: pkg.Version}},
		)
	}

	bytes, err := json.Marshal(&doc)

	if err != nil {
		log.Errorf("failed to marshal json (presenter=json): %w", err)
	}

	_, err = output.Write(bytes)
	return err
}
