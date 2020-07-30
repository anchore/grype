package ui

import (
	"github.com/wagoodman/go-partybus"
)

type UI func(<-chan error, *partybus.Subscription) error
