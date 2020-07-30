package ui

import (
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/ui/common"
	syftEvent "github.com/anchore/syft/syft/event"
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
			if e.Type == syftEvent.CatalogerFinished {
				err := common.VulnerabilityScanningFinishedHandler(e)
				if err != nil {
					log.Errorf("unable to show catalog image finished event: %+v", err)
				}

				// this is the last expected event
				break eventLoop
			}
		}
	}

	return nil
}
