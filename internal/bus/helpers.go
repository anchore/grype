package bus

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/redact"
)

func Exit() {
	Publish(clio.ExitEvent(false))
}

func ExitWithInterrupt() {
	Publish(clio.ExitEvent(true))
}

func Report(report string) {
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: redact.Apply(report),
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}
