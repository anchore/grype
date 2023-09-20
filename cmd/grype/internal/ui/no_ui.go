package ui

import (
	"os"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/event"
)

var _ clio.UI = (*NoUI)(nil)

type NoUI struct {
	finalizeEvents []partybus.Event
	subscription   partybus.Unsubscribable
	quiet          bool
}

func None(quiet bool) *NoUI {
	return &NoUI{
		quiet: quiet,
	}
}

func (n *NoUI) Setup(subscription partybus.Unsubscribable) error {
	n.subscription = subscription
	return nil
}

func (n *NoUI) Handle(e partybus.Event) error {
	switch e.Type {
	case event.CLIReport, event.CLINotification:
		// keep these for when the UI is terminated to show to the screen (or perform other events)
		n.finalizeEvents = append(n.finalizeEvents, e)
	}
	return nil
}

func (n NoUI) Teardown(_ bool) error {
	return newPostUIEventWriter(os.Stdout, os.Stderr).write(n.quiet, n.finalizeEvents...)
}
