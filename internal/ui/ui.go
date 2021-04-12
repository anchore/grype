package ui

import (
	"context"

	"github.com/wagoodman/go-partybus"
)

type UI func(context.Context, <-chan error, *partybus.Subscription) chan error
