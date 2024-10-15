package commands

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
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
