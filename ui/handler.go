package ui

import (
	"context"
	"sync"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	syftUI "github.com/anchore/syft/ui"
	griffonEvent "github.com/nextlinux/griffon/griffon/event"
)

type Handler struct {
	syftHandler *syftUI.Handler
}

func NewHandler() *Handler {
	return &Handler{
		syftHandler: syftUI.NewHandler(),
	}
}

func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case griffonEvent.VulnerabilityScanningStarted,
		griffonEvent.UpdateVulnerabilityDatabase,
		griffonEvent.DatabaseDiffingStarted:
		return true
	default:
		return r.syftHandler.RespondsTo(event)
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case griffonEvent.VulnerabilityScanningStarted:
		return r.VulnerabilityScanningStartedHandler(ctx, fr, event, wg)
	case griffonEvent.UpdateVulnerabilityDatabase:
		return r.UpdateVulnerabilityDatabaseHandler(ctx, fr, event, wg)
	case griffonEvent.DatabaseDiffingStarted:
		return r.DatabaseDiffingStartedHandler(ctx, fr, event, wg)
	default:
		return r.syftHandler.Handle(ctx, fr, event, wg)
	}
}
