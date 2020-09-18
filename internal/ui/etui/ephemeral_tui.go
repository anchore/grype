package etui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	grypeEvent "github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/grypeerr"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/logger"
	"github.com/anchore/grype/internal/ui/common"
	grypeUI "github.com/anchore/grype/ui"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// TODO: specify per-platform implementations with build tags

func setupScreen(output *os.File) *frame.Frame {
	config := frame.Config{
		PositionPolicy: frame.PolicyFloatForward,
		// only report output to stderr, reserve report output for stdout
		Output: output,
	}

	fr, err := frame.New(config)
	if err != nil {
		log.Errorf("failed to create screen object: %+v", err)
		return nil
	}
	return fr
}

// nolint:funlen,gocognit
func OutputToEphemeralTUI(workerErrs <-chan error, subscription *partybus.Subscription) error {
	output := os.Stderr

	// prep the logger to not clobber the screen from now on (logrus only)
	logBuffer := bytes.NewBufferString("")
	logWrapper, ok := log.Log.(*logger.LogrusLogger)
	if ok {
		logWrapper.Logger.SetOutput(logBuffer)
	}

	// hide cursor
	_, _ = fmt.Fprint(output, "\x1b[?25l")
	// show cursor
	defer fmt.Fprint(output, "\x1b[?25h")

	fr := setupScreen(output)
	if fr == nil {
		return fmt.Errorf("unable to setup screen")
	}
	var isClosed bool
	defer func() {
		if !isClosed {
			fr.Close()
			frame.Close()
			// flush any errors to the screen before the report
			fmt.Fprint(output, logBuffer.String())
		}
		logWrapper, ok := log.Log.(*logger.LogrusLogger)
		if ok {
			logWrapper.Logger.SetOutput(output)
		}
	}()

	var err error
	var wg = &sync.WaitGroup{}
	events := subscription.Events()
	ctx := context.Background()
	grypeUIHandler := grypeUI.NewHandler()

	var errResult error
	for {
		select {
		case err, ok := <-workerErrs:
			if err != nil {
				if errors.Is(err, grypeerr.ErrAboveSeverityThreshold) {
					errResult = err
					continue
				}
				return err
			}
			if !ok {
				// worker completed
				workerErrs = nil
			}
		case e, ok := <-events:
			if !ok {
				// event bus closed
				events = nil
			}
			switch {
			case grypeUIHandler.RespondsTo(e):
				if err = grypeUIHandler.Handle(ctx, fr, e, wg); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

			case e.Type == grypeEvent.AppUpdateAvailable:
				if err = appUpdateAvailableHandler(ctx, fr, e, wg); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

			case e.Type == grypeEvent.VulnerabilityScanningFinished:
				// we may have other background processes still displaying progress, wait for them to
				// finish before discontinuing dynamic content and showing the final report
				wg.Wait()
				fr.Close()
				// TODO: there is a race condition within frame.Close() that sometimes leads to an extra blank line being output
				frame.Close()
				isClosed = true

				// flush any errors to the screen before the report
				fmt.Fprint(output, logBuffer.String())

				if err := common.VulnerabilityScanningFinishedHandler(e); err != nil {
					log.Errorf("unable to show %s event: %+v", e.Type, err)
				}

				// this is the last expected event
				events = nil
			}
		case <-ctx.Done():
			return grypeerr.NewExpectedErr("cancelled: %w", ctx.Err())
		}
		if events == nil && workerErrs == nil {
			break
		}
	}

	return errResult
}
