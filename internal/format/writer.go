package format

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

type ScanResultWriter interface {
	Write(result models.PresenterConfig) error
}

var _ ScanResultWriter = (*scanResultMultiWriter)(nil)

var _ interface {
	io.Closer
	ScanResultWriter
} = (*scanResultStreamWriter)(nil)

// MakeScanResultWriter creates a ScanResultWriter for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, ScanResultWriter.Close() should be called
func MakeScanResultWriter(outputs []string, defaultFile string, cfg PresentationConfig) (ScanResultWriter, error) {
	outputOptions, err := parseOutputFlags(outputs, defaultFile, cfg)
	if err != nil {
		return nil, err
	}

	writer, err := newMultiWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// MakeScanResultWriterForFormat creates a ScanResultWriter for the given format or returns an error.
func MakeScanResultWriterForFormat(f string, path string, cfg PresentationConfig) (ScanResultWriter, error) {
	format := Parse(f)

	if format == UnknownFormat {
		return nil, fmt.Errorf(`unsupported output format "%s", supported formats are: %+v`, f, AvailableFormats)
	}

	writer, err := newMultiWriter(newWriterDescription(format, path, cfg))
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseOutputFlags utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOutputFlags(outputs []string, defaultFile string, cfg PresentationConfig) (out []scanResultWriterDescription, errs error) {
	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, TableFormat.String())
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format name is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output formatName, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		format := Parse(name)

		if format == UnknownFormat {
			errs = multierror.Append(errs, fmt.Errorf(`unsupported output format "%s", supported formats are: %+v`, name, AvailableFormats))
			continue
		}

		out = append(out, newWriterDescription(format, file, cfg))
	}
	return out, errs
}

// scanResultWriterDescription Format and path strings used to create ScanResultWriter
type scanResultWriterDescription struct {
	Format Format
	Path   string
	Cfg    PresentationConfig
}

func newWriterDescription(f Format, p string, cfg PresentationConfig) scanResultWriterDescription {
	expandedPath, err := homedir.Expand(p)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", p, err)
		// ignore errors
		expandedPath = p
	}
	return scanResultWriterDescription{
		Format: f,
		Path:   expandedPath,
		Cfg:    cfg,
	}
}

// scanResultMultiWriter holds a list of child ScanResultWriters to apply all Write and Close operations to
type scanResultMultiWriter struct {
	writers []ScanResultWriter
}

// newMultiWriter create all report writers from input options; if a file is not specified the given defaultWriter is used
func newMultiWriter(options ...scanResultWriterDescription) (_ *scanResultMultiWriter, err error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &scanResultMultiWriter{}

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.writers = append(out.writers, &scanResultPublisher{
				format: option.Format,
				cfg:    option.Cfg,
			})
		default:
			// create any missing subdirectories
			dir := filepath.Dir(option.Path)
			if dir != "" {
				s, err := os.Stat(dir)
				if err != nil {
					err = os.MkdirAll(dir, 0755) // maybe should be os.ModePerm ?
					if err != nil {
						return nil, err
					}
				} else if !s.IsDir() {
					return nil, fmt.Errorf("output path does not contain a valid directory: %s", option.Path)
				}
			}
			fileOut, err := os.OpenFile(option.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return nil, fmt.Errorf("unable to create report file: %w", err)
			}
			out.writers = append(out.writers, &scanResultStreamWriter{
				format: option.Format,
				out:    fileOut,
				cfg:    option.Cfg,
			})
		}
	}

	return out, nil
}

// Write writes the result to all writers
func (m *scanResultMultiWriter) Write(s models.PresenterConfig) (errs error) {
	for _, w := range m.writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to write result: %w", err))
		}
	}
	return errs
}

// scanResultStreamWriter implements ScanResultWriter for a given format and io.Writer, also providing a close function for cleanup
type scanResultStreamWriter struct {
	format Format
	cfg    PresentationConfig
	out    io.Writer
}

// Write the provided result to the data stream
func (w *scanResultStreamWriter) Write(s models.PresenterConfig) error {
	pres := GetPresenter(w.format, w.cfg, s)
	if err := pres.Present(w.out); err != nil {
		return fmt.Errorf("unable to encode result: %w", err)
	}
	return nil
}

// Close any resources, such as open files
func (w *scanResultStreamWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// scanResultPublisher implements ScanResultWriter that publishes results to the event bus
type scanResultPublisher struct {
	format Format
	cfg    PresentationConfig
}

// Write the provided result to the data stream
func (w *scanResultPublisher) Write(s models.PresenterConfig) error {
	pres := GetPresenter(w.format, w.cfg, s)
	buf := &bytes.Buffer{}
	if err := pres.Present(buf); err != nil {
		return fmt.Errorf("unable to encode result: %w", err)
	}

	bus.Report(buf.String())
	return nil
}
