package ui

import (
	"context"
	"sync"

	grypeEvent "github.com/anchore/grype/grype/event"
	syftUI "github.com/anchore/syft/ui"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
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
	case grypeEvent.VulnerabilityScanningStarted, grypeEvent.UpdateVulnerabilityDatabase:
		return true
	default:
		return r.syftHandler.RespondsTo(event)
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case grypeEvent.VulnerabilityScanningStarted:
		return VulnerabilityScanningStartedHandler(ctx, fr, event, wg)

	case grypeEvent.UpdateVulnerabilityDatabase:
		return DownloadingVulnerabilityDatabaseHandler(ctx, fr, event, wg)
	default:
		return r.syftHandler.Handle(ctx, fr, event, wg)
	}
}
