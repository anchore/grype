package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
)

// eventLoop listens to worker errors (from execution path), worker events (from a partybus subscription), and
// signal interrupts. Is responsible for handling each event relative to a given UI an to coordinate eventing until
// an eventual graceful exit.
// nolint:gocognit
func eventLoop(workerErrs <-chan error, signals <-chan os.Signal, subscription *partybus.Subscription, cleanupFn func(), uxs ...ui.UI) error {
	defer cleanupFn()
	events := subscription.Events()
	var err error
	var ux ui.UI

	if ux, err = setupUI(subscription.Unsubscribe, uxs...); err != nil {
		return err
	}

	var retErr error
	var forceTeardown bool

	for {
		if workerErrs == nil && events == nil {
			break
		}
		select {
		case err, isOpen := <-workerErrs:
			if !isOpen {
				workerErrs = nil
				continue
			}
			if err != nil {
				// capture the error from the worker and unsubscribe to complete a graceful shutdown
				retErr = multierror.Append(retErr, err)
				if err := subscription.Unsubscribe(); err != nil {
					retErr = multierror.Append(retErr, err)
				}
				// the worker has exited, we may have been mid-handling events for the UI which should now be
				// ignored, in which case forcing a teardown of the UI irregardless of the state is required.
				forceTeardown = true
			}
		case e, isOpen := <-events:
			if !isOpen {
				events = nil
				continue
			}

			if err := ux.Handle(e); err != nil {
				if errors.Is(err, partybus.ErrUnsubscribe) {
					events = nil
				} else {
					retErr = multierror.Append(retErr, err)
					// TODO: should we unsubscribe? should we try to halt execution? or continue?
				}
			}
		case <-signals:
			// ignore further results from any event source and exit ASAP, but ensure that all cache is cleaned up.
			// we ignore further errors since cleaning up the tmp directories will affect running catalogers that are
			// reading/writing from/to their nested temp dirs. This is acceptable since we are bailing without result.

			// TODO: potential future improvement would be to pass context into workers with a cancel function that is
			// to the event loop. In this way we can have a more controlled shutdown even at the most nested levels
			// of processing.
			events = nil
			workerErrs = nil
			forceTeardown = true
		}
	}

	if err := ux.Teardown(forceTeardown); err != nil {
		retErr = multierror.Append(retErr, err)
	}

	return retErr
}

// setupUI takes one or more UIs that responds to events and takes a event bus unsubscribe function for use
// during teardown. With the given UIs, the first UI which the ui.Setup() function does not return an error
// will be utilized in execution. Providing a set of UIs allows for the caller to provide graceful fallbacks
// when there are environmental problem (e.g. unable to setup a TUI with the current TTY).
func setupUI(unsubscribe func() error, uis ...ui.UI) (ui.UI, error) {
	for _, ux := range uis {
		if err := ux.Setup(unsubscribe); err != nil {
			log.Warnf("unable to setup given UI, falling back to alternative UI: %+v", err)
			continue
		}

		return ux, nil
	}
	return nil, fmt.Errorf("unable to setup any UI")
}
