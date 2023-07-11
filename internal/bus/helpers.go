package bus

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/event"
)

func Exit() {
	Publish(partybus.Event{
		Type: event.CLIExit,
	})
}

func Report(report string) {
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}
