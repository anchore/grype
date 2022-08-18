package ui

import (
	"fmt"
	"io"

	"github.com/wagoodman/go-partybus"

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
)

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

func handleNonRootCommandFinished(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	result, err := grypeEventParsers.ParseNonRootCommandFinished(event)
	if err != nil {
		return fmt.Errorf("bad NonRootCommandFinished event: %w", err)
	}

	if _, err := reportOutput.Write([]byte(*result)); err != nil {
		return fmt.Errorf("unable to show vulnerability report: %w", err)
	}
	return nil
}
