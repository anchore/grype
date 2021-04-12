package etui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/logger"
	grypeUI "github.com/anchore/grype/ui"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"
)

// TODO: specify per-platform implementations with build tags

// EphemeralTUI creates and manages a short-lived terminal UI to display events from other asynchronous
// processing.
func EphemeralTUI(ctx context.Context, workerErrs <-chan error, subscription *partybus.Subscription) chan error {
	result := make(chan error)
	go func() {
		fr, tearDownETUI, err := setUpETUI()
		defer func() {
			// We definitely want to tear down the ETUI regardless of what else happens!
			if tearDownETUI != nil {
				tearDownETUI()
			}
		}()
		if err != nil {
			result <- err
			return
		}

		result <- <-handleAllEvents(ctx, fr, workerErrs, subscription.Events())
	}()
	return result
}

func setUpETUI() (fr *frame.Frame, teardown func(), err error) {
	output := os.Stderr

	var teardownSteps []func()
	defer func() {
		teardown = func() {
			// TODO: consider reversing order of steps to achieve a FILO effect
			for _, doStep := range teardownSteps {
				doStep()
			}
		}
	}()

	// prep the logger to not clobber the screen from now on (logrus only)
	logBuffer := bytes.NewBufferString("")
	logWrapper, ok := log.Log.(*logger.LogrusLogger)
	if ok {
		logWrapper.Logger.SetOutput(logBuffer)
	}

	// hide cursor
	_, _ = fmt.Fprint(output, "\x1b[?25l")
	teardownSteps = append(teardownSteps, func() {
		// show cursor
		fmt.Fprint(output, "\x1b[?25h")
	})

	fr = setUpScreen(output)
	if fr == nil {
		err = fmt.Errorf("unable to setup screen")
		return
	}

	teardownSteps = append(teardownSteps, func() {
		fr.Close()
		frame.Close()
		// flush any errors to the screen before the report
		fmt.Fprint(output, logBuffer.String())

		logWrapper, ok := log.Log.(*logger.LogrusLogger)
		if ok {
			logWrapper.Logger.SetOutput(output)
		}
	})

	return fr, teardown, nil
}

func setUpScreen(output *os.File) *frame.Frame {
	config := frame.Config{
		PositionPolicy: frame.PolicyFloatForward,
		// only use stderr, reserve stdout for report output
		Output: output,
	}

	fr, err := frame.New(config)
	if err != nil {
		log.Errorf("failed to create screen object: %+v", err)
		return nil
	}

	return fr
}

func handleAllEvents(ctx context.Context, fr *frame.Frame, workerErrs <-chan error, events <-chan partybus.Event) chan error {
	result := make(chan error)
	go func() {
		defer close(result)

		grypeUIHandler := grypeUI.NewHandler()
		wg := new(sync.WaitGroup)
		defer wg.Wait()

		for {
			select {
			case <-ctx.Done():
				// TODO: Needless to say, DO NOT MERGE with this.
				//  Taking this out makes obvious an existing race condition that can be seen when using the table
				//  presenter with very few rows, where extra blank lines are inserted without carriage returns — sometimes.
				time.Sleep(time.Second)

				return
			case err := <-workerErrs:
				result <- err
			case e := <-events:
				if grypeUIHandler.RespondsTo(e) {
					if err := grypeUIHandler.Handle(ctx, fr, e, wg); err != nil {
						log.Errorf("unable to show %s event: %+v", e.Type, err)
					}
				}
			}
		}
	}()
	return result
}
