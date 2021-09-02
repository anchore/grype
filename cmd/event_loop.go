package cmd

import (
	"errors"
	"os"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
)

// eventLoop listens to worker errors (from execution path), worker events (from a partybus subscription), and
// signal interrupts. Is responsible for handling each event relative to a given UI an to coordinate eventing until
// an eventual graceful exit.
// nolint:gocognit,funlen
func eventLoop(workerErrs <-chan error, signals <-chan os.Signal, subscription *partybus.Subscription, ux ui.UI, cleanupFn func()) error {
	defer cleanupFn()
	events := subscription.Events()
	var err error
	if ux, err = setupUI(subscription.Unsubscribe, ux); err != nil {
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
			}
		case e, isOpen := <-events:
			if !isOpen {
				events = nil
				continue
			}

			if err := ux.Handle(e); err != nil {
				if errors.Is(err, partybus.ErrUnsubscribe) {
					log.Warnf("unable to unsubscribe from the event bus")
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

func setupUI(unsubscribe func() error, ux ui.UI) (ui.UI, error) {
	if err := ux.Setup(unsubscribe); err != nil {
		// replace the existing UI with a (simpler) logger UI
		ux = ui.NewLoggerUI()
		if err := ux.Setup(unsubscribe); err != nil {
			// something is very wrong, bail.
			return ux, err
		}
		log.Errorf("unable to setup given UI, falling back to logger: %+v", err)
	}
	return ux, nil
}
