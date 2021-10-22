package ui

import (
	"github.com/wagoodman/go-partybus"
)

type UI interface {
	Setup(unsubscribe func() error) error
	partybus.Handler
	Teardown(force bool) error
}
