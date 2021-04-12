package ui

import (
	"context"

	"github.com/wagoodman/go-partybus"
)

func loggerUI(ctx context.Context, workerErrs <-chan error, subscription *partybus.Subscription) chan error {
	result := make(chan error)

	go func() {
		defer close(result)

		events := subscription.Events()

		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-workerErrs:
				if err != nil {
					result <- err
					return
				}
				if !ok {
					// worker completed
					workerErrs = nil
				}
			case _, ok := <-events:
				if !ok {
					// event bus closed
					events = nil
				}
			}
			if events == nil && workerErrs == nil {
				break
			}
		}
	}()

	return result
}
