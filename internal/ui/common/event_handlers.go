package common

import (
	"fmt"
	"os"

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
	"github.com/wagoodman/go-partybus"
)

func VulnerabilityScanningFinishedHandler(event partybus.Event) error {
	// show the report to stdout
	pres, err := grypeEventParsers.ParseVulnerabilityScanningFinished(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(os.Stdout); err != nil {
		return fmt.Errorf("unable to show vulnerability report: %w", err)
	}
	return nil
}
