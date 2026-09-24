// Package jsonl provides a presenter that emits one JSON object per line
// (the JSON Lines / ndjson convention). Each line is a single match record,
// suitable for streaming to tools like jq, xargs, or downstream processors
// that accept newline-delimited JSON on stdin.
//
// See https://github.com/anchore/grype/issues/1159 for the motivating use case.
package jsonl

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/presenter/models"
)

// Presenter writes the matches contained in the document one per line as
// JSON objects. Document-level metadata (descriptor, source, distro,
// ignoredMatches, alertsByPackage) is intentionally omitted — JSON Lines is
// a flat record stream by design. Consumers that need that metadata should
// use the standard `json` format.
type Presenter struct {
	document models.Document
}

// NewPresenter returns a new JSON Lines presenter.
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		document: pb.Document,
	}
}

// Present writes one JSON-encoded match per line, terminated by a newline.
// When there are no matches, no output is written — this is the standard
// jsonl convention (an empty file is a valid empty stream).
func (p *Presenter) Present(output io.Writer) error {
	enc := json.NewEncoder(output)
	// match the json presenter's behavior so values aren't HTML-escaped
	enc.SetEscapeHTML(false)
	// json.Encoder.Encode appends a newline after every value, so the output
	// is naturally newline-delimited.
	for _, m := range p.document.Matches {
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	return nil
}
