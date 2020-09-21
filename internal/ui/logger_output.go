package ui

import (
	"errors"

	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui/common"
	"github.com/wagoodman/go-partybus"
)

func LoggerUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	events := subscription.Events()
	var errResult error
	for {
		select {
		case err, ok := <-workerErrs:
			if err != nil {
				if errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
					errResult = err
					continue
				}
				return err
			}
			if !ok {
				// worker completed
				workerErrs = nil
			}
		case e, ok := <-events:
			if !ok {
				// event bus closed
				events = nil
			}

			// ignore all events except for the final event
			if e.Type == grypeEvent.VulnerabilityScanningFinished {
				err := common.VulnerabilityScanningFinishedHandler(e)
				if err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

				// this is the last expected event
				events = nil
			}
		}
		if events == nil && workerErrs == nil {
			break
		}
	}
	return errResult
}
