package ui

import (
	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui/common"
	"github.com/wagoodman/go-partybus"
)

func LoggerUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	events := subscription.Events()
eventLoop:
	for {
		select {
		case err := <-workerErrs:
			if err != nil {
				return err
			}
		case e, ok := <-events:
			if !ok {
				// event bus closed...
				break eventLoop
			}

			// ignore all events except for the final event
			if e.Type == grypeEvent.VulnerabilityScanningFinished {
				err := common.VulnerabilityScanningFinishedHandler(e)
				if err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

				// this is the last expected event
				break eventLoop
			}
		}
	}

	return nil
}
