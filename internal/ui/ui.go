package ui

import (
	"fmt"
	"io"

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
	"github.com/wagoodman/go-partybus"
)

type UI interface {
	Setup(unsubscribe func() error) error
	partybus.Handler
	Teardown(force bool) error
}

func handleVulnerabilityScanningFinished(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	pres, err := grypeEventParsers.ParseVulnerabilityScanningFinished(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(reportOutput); err != nil {
		return fmt.Errorf("unable to show vulnerability report: %w", err)
	}
	return nil
}
