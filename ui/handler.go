package ui

import (
	"context"
	"sync"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	grypeEvent "github.com/anchore/grype/grype/event"
	syftUI "github.com/anchore/syft/ui"
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
	case grypeEvent.VulnerabilityScanningStarted,
		grypeEvent.UpdateVulnerabilityDatabase,
		grypeEvent.AttestationVerified,
		grypeEvent.AttestationVerificationSkipped,
		grypeEvent.DatabaseDiffingStarted:
		return true
	default:
		return r.syftHandler.RespondsTo(event)
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case grypeEvent.VulnerabilityScanningStarted:
		return r.VulnerabilityScanningStartedHandler(ctx, fr, event, wg)
	case grypeEvent.UpdateVulnerabilityDatabase:
		return r.UpdateVulnerabilityDatabaseHandler(ctx, fr, event, wg)
	case grypeEvent.AttestationVerified:
		return r.VerifyAttestationSignature(ctx, fr, event, wg)
	case grypeEvent.AttestationVerificationSkipped:
		return r.SkippedAttestationVerification(ctx, fr, event, wg)
	case grypeEvent.DatabaseDiffingStarted:
		return r.DatabaseDiffingStartedHandler(ctx, fr, event, wg)
	default:
		return r.syftHandler.Handle(ctx, fr, event, wg)
	}
}
