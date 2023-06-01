package ui

import (
	"io"

	"github.com/wagoodman/go-partybus"

	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/log"
)

type loggerUI struct {
	unsubscribe  func() error
	reportOutput io.Writer
}

// NewLoggerUI writes all events to the common application logger and writes the final report to the given writer.
func NewLoggerUI(reportWriter io.Writer) UI {
	return &loggerUI{
		reportOutput: reportWriter,
	}
}

func (l *loggerUI) Setup(unsubscribe func() error) error {
	l.unsubscribe = unsubscribe
	return nil
}

func (l loggerUI) Handle(event partybus.Event) error {
	switch event.Type {
	case grypeEvent.PresentationStarted:
		if err := handlePresentationStarted(event, l.reportOutput); err != nil {
			log.Warnf("unable to show presentation started event: %+v", err)
		}
	case grypeEvent.NonRootCommandFinished:
		if err := handleNonRootCommandFinished(event, l.reportOutput); err != nil {
			log.Warnf("unable to show command finished event: %+v", err)
		}
	// ignore all events except for the final events
	default:
		return nil
	}

	// this is the last expected event, stop listening to events
	return l.unsubscribe()
}

func (l loggerUI) Teardown(_ bool) error {
	return nil
}
