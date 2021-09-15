package ui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/logger"
	"github.com/anchore/grype/ui"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// ephemeralTerminalUI provides an "ephemeral" terminal user interface to display the application state dynamically.
// The terminal is placed into raw mode and the cursor is manipulated to allow for a dynamic, multi-line
// UI (provided by the jotframe lib), for this reason all other application mechanisms that write to the screen
// must be suppressed before starting (such as logs); since bytes in the device and in application memory combine to make
// a shared state, bytes coming from elsewhere to the screen will disrupt this state.
//
// This UI is primarily driven off of events from the event bus, creating single-line terminal widgets to represent a
// published element on the event bus, typically polling the element for the latest state. This allows for the UI to
// control update frequency to the screen, provide "liveness" indications that are interpolated between bus events,
// and overall loosely couple the bus events from screen interactions.
//
// By convention, all elements published on the bus should be treated as read-only, and publishers on the bus should
// attempt to enforce this when possible by wrapping complex objects with interfaces to prescribe interactions. Also by
// convention, each new event that the UI should respond to should be added either in this package as a handler function,
// or in the shared ui package as a function on the main handler object. All handler functions should be completed
// processing an event before the ETUI exits (coordinated with a sync.WaitGroup)
type ephemeralTerminalUI struct {
	unsubscribe  func() error
	handler      *ui.Handler
	waitGroup    *sync.WaitGroup
	frame        *frame.Frame
	logBuffer    *bytes.Buffer
	uiOutput     *os.File
	reportOutput io.Writer
}

// NewEphemeralTerminalUI writes all events to a TUI and writes the final report to the given writer.
func NewEphemeralTerminalUI(reportWriter io.Writer) UI {
	return &ephemeralTerminalUI{
		handler:      ui.NewHandler(),
		waitGroup:    &sync.WaitGroup{},
		uiOutput:     os.Stderr,
		reportOutput: reportWriter,
	}
}

func (h *ephemeralTerminalUI) Setup(unsubscribe func() error) error {
	h.unsubscribe = unsubscribe
	hideCursor(h.uiOutput)

	// prep the logger to not clobber the screen from now on (logrus only)
	h.logBuffer = bytes.NewBufferString("")
	logWrapper, ok := log.Log.(*logger.LogrusLogger)
	if ok {
		logWrapper.Logger.SetOutput(h.logBuffer)
	}

	return h.openScreen()
}

func (h *ephemeralTerminalUI) Handle(event partybus.Event) error {
	ctx := context.Background()
	switch {
	case h.handler.RespondsTo(event):
		if err := h.handler.Handle(ctx, h.frame, event, h.waitGroup); err != nil {
			log.Errorf("unable to show %s event: %+v", event.Type, err)
		}

	case event.Type == grypeEvent.AppUpdateAvailable:
		if err := handleAppUpdateAvailable(ctx, h.frame, event, h.waitGroup); err != nil {
			log.Errorf("unable to show %s event: %+v", event.Type, err)
		}

	case event.Type == grypeEvent.VulnerabilityScanningFinished:
		// we need to close the screen now since signaling the the presenter is ready means that we
		// are about to write bytes to stdout, so we should reset the terminal state first
		h.closeScreen(false)

		if err := handleVulnerabilityScanningFinished(event, h.reportOutput); err != nil {
			log.Errorf("unable to show %s event: %+v", event.Type, err)
		}

		// this is the last expected event, stop listening to events
		return h.unsubscribe()
	}
	return nil
}

func (h *ephemeralTerminalUI) openScreen() error {
	config := frame.Config{
		PositionPolicy: frame.PolicyFloatForward,
		// only report output to stderr, reserve report output for stdout
		Output: h.uiOutput,
	}

	fr, err := frame.New(config)
	if err != nil {
		return fmt.Errorf("failed to create the screen object: %w", err)
	}
	h.frame = fr

	return nil
}

func (h *ephemeralTerminalUI) closeScreen(force bool) {
	// we may have other background processes still displaying progress, wait for them to
	// finish before discontinuing dynamic content and showing the final report
	if !h.frame.IsClosed() {
		if !force {
			h.waitGroup.Wait()
		}
		h.frame.Close()
		// TODO: there is a race condition within frame.Close() that sometimes leads to an extra blank line being output
		frame.Close()

		// only flush the log on close
		h.flushLog()
	}
}

func (h *ephemeralTerminalUI) flushLog() {
	// flush any errors to the screen before the report
	logWrapper, ok := log.Log.(*logger.LogrusLogger)
	if ok {
		fmt.Fprint(logWrapper.Output, h.logBuffer.String())
		logWrapper.Logger.SetOutput(h.uiOutput)
	} else {
		fmt.Fprint(h.uiOutput, h.logBuffer.String())
	}
}

func (h *ephemeralTerminalUI) Teardown(force bool) error {
	h.closeScreen(force)
	showCursor(h.uiOutput)
	return nil
}

func hideCursor(output io.Writer) {
	fmt.Fprint(output, "\x1b[?25l")
}

func showCursor(output io.Writer) {
	fmt.Fprint(output, "\x1b[?25h")
}
