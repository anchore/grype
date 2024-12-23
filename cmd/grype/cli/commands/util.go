package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/internal/ui"
)

func disableUI(app clio.Application) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		type Stater interface {
			State() *clio.State
		}

		state := app.(Stater).State()
		state.UI = clio.NewUICollection(ui.None(state.Config.Log.Quiet))

		return nil
	}
}

func stderrPrintLnf(message string, args ...interface{}) error {
	if !strings.HasSuffix(message, "\n") {
		message += "\n"
	}
	_, err := fmt.Fprintf(os.Stderr, message, args...)
	return err
}

// parallel takes a set of functions and runs them in parallel, capturing all errors returned and
// returning the single error returned by one of the parallel funcs, or a multierror.Error with all
// the errors if more than one
func parallel(funcs ...func() error) error {
	errs := parallelMapped(funcs...)
	if len(errs) > 0 {
		values := maps.Values(errs)
		if len(values) == 1 {
			return values[0]
		}
		return multierror.Append(nil, values...)
	}
	return nil
}

// parallelMapped takes a set of functions and runs them in parallel, capturing all errors returned in
// a map indicating which func, by index returned which error
func parallelMapped(funcs ...func() error) map[int]error {
	errs := map[int]error{}
	errorLock := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	wg.Add(len(funcs))
	for i, fn := range funcs {
		go func(i int, fn func() error) {
			defer wg.Done()
			err := fn()
			if err != nil {
				errorLock.Lock()
				defer errorLock.Unlock()
				errs[i] = err
			}
		}(i, fn)
	}
	wg.Wait()
	return errs
}

func appendErrors(errs error, err ...error) error {
	if errs == nil {
		switch len(err) {
		case 0:
			return nil
		case 1:
			return err[0]
		}
	}
	return multierror.Append(errs, err...)
}

func newTable(output io.Writer) *tablewriter.Table {
	// we use a trimming writer to ensure that the table is not padded with spaces when there is a single long row
	// and several short rows. AFAICT there is no table setting to control this behavior. Why do it as a writer? So
	// we don't need to buffer the entire table in memory before writing it out.
	table := tablewriter.NewWriter(newTrimmingWriter(output))
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)
	return table
}

// trimmingWriter is a writer that trims whitespace from the end of each line. It is assumed that whole lines are
// passed to Write() calls (no partial lines).
type trimmingWriter struct {
	output io.Writer
	buffer bytes.Buffer
}

func newTrimmingWriter(w io.Writer) *trimmingWriter {
	return &trimmingWriter{output: w}
}

func (tw *trimmingWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		switch b {
		case '\n':
			// write a newline and discard any buffered spaces
			_, err := tw.output.Write([]byte{'\n'})
			if err != nil {
				return 0, err
			}
			tw.buffer.Reset()
		case ' ', '\t':
			// buffer spaces and tabs
			tw.buffer.WriteByte(b)
		default:
			// write any buffered spaces, then the non-whitespace character
			if tw.buffer.Len() > 0 {
				_, err := tw.output.Write(tw.buffer.Bytes())
				if err != nil {
					return 0, err
				}
				tw.buffer.Reset()
			}
			_, err := tw.output.Write([]byte{b})
			if err != nil {
				return 0, err
			}
		}
	}

	return len(p), nil
}
