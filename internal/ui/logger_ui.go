package ui

import (
	"io"

	"github.com/wagoodman/go-partybus"

	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/internal/log"
)

type loggerUI struct {
	unsubscribe  func() error
	reportOutput io.Writer
	reports      []string
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

func (l *loggerUI) Handle(event partybus.Event) error {
	switch event.Type {
	case grypeEvent.CLIReport:
		_, report, err := parsers.ParseCLIReport(event)
		if err != nil {
			log.Errorf("unable to show %s event: %+v", event.Type, err)
			break
		}
		l.reports = append(l.reports, report)
	case grypeEvent.CLIExit:
		// this is the last expected event, stop listening to events
		return l.unsubscribe()
	}
	return nil
}

func (l loggerUI) Teardown(_ bool) error {
	for _, report := range l.reports {
		_, err := l.reportOutput.Write([]byte(report))
		if err != nil {
			return err
		}
	}
	return nil
}
