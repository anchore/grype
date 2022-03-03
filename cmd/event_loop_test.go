package cmd

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/ui"
)

var _ ui.UI = (*uiMock)(nil)

type uiMock struct {
	t           *testing.T
	finalEvent  partybus.Event
	unsubscribe func() error
	mock.Mock
}

func (u *uiMock) Setup(unsubscribe func() error) error {
	u.t.Logf("UI Setup called")
	u.unsubscribe = unsubscribe
	return u.Called(unsubscribe).Error(0)
}

func (u *uiMock) Handle(event partybus.Event) error {
	u.t.Logf("UI Handle called: %+v", event.Type)
	if event == u.finalEvent {
		assert.NoError(u.t, u.unsubscribe())
	}
	return u.Called(event).Error(0)
}

func (u *uiMock) Teardown(_ bool) error {
	u.t.Logf("UI Teardown called")
	return u.Called().Error(0)
}

func Test_eventLoop_gracefulExit(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		finalEvent := partybus.Event{
			Type: event.VulnerabilityScanningFinished,
		}

		worker := func() <-chan error {
			ret := make(chan error)
			go func() {
				t.Log("worker running")
				// send an empty item (which is ignored) ensuring we've entered the select statement,
				// then close (a partial shutdown).
				ret <- nil
				t.Log("worker sent nothing")
				close(ret)
				t.Log("worker closed")
				// do the other half of the shutdown
				testBus.Publish(finalEvent)
				t.Log("worker published final event")
			}()
			return ret
		}

		signaler := func() <-chan os.Signal {
			return nil
		}

		ux := &uiMock{
			t:          t,
			finalEvent: finalEvent,
		}

		// ensure the mock sees at least the final event
		ux.On("Handle", finalEvent).Return(nil)
		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(nil)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		assert.NoError(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func Test_eventLoop_workerError(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		workerErr := fmt.Errorf("worker error")

		worker := func() <-chan error {
			ret := make(chan error)
			go func() {
				t.Log("worker running")
				// send an empty item (which is ignored) ensuring we've entered the select statement,
				// then close (a partial shutdown).
				ret <- nil
				t.Log("worker sent nothing")
				ret <- workerErr
				t.Log("worker sent error")
				close(ret)
				t.Log("worker closed")
				// note: NO final event is fired
			}()
			return ret
		}

		signaler := func() <-chan os.Signal {
			return nil
		}

		ux := &uiMock{
			t: t,
		}

		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(nil)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		// ensure we see an error returned
		assert.ErrorIs(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
			workerErr,
			"should have seen a worker error, but did not",
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func Test_eventLoop_unsubscribeError(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		finalEvent := partybus.Event{
			Type: event.VulnerabilityScanningFinished,
		}

		worker := func() <-chan error {
			ret := make(chan error)
			go func() {
				t.Log("worker running")
				// send an empty item (which is ignored) ensuring we've entered the select statement,
				// then close (a partial shutdown).
				ret <- nil
				t.Log("worker sent nothing")
				close(ret)
				t.Log("worker closed")
				// do the other half of the shutdown
				testBus.Publish(finalEvent)
				t.Log("worker published final event")
			}()
			return ret
		}

		signaler := func() <-chan os.Signal {
			return nil
		}

		ux := &uiMock{
			t:          t,
			finalEvent: finalEvent,
		}

		// ensure the mock sees at least the final event... note the unsubscribe error here
		ux.On("Handle", finalEvent).Return(partybus.ErrUnsubscribe)
		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(nil)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		// unsubscribe errors should be handled and ignored, not propagated. We are additionally asserting that
		// this case is handled as a controlled shutdown (this test should not timeout)
		assert.NoError(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func Test_eventLoop_handlerError(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		finalEvent := partybus.Event{
			Type:  event.VulnerabilityScanningFinished,
			Error: fmt.Errorf("unable to create presenter"),
		}

		worker := func() <-chan error {
			ret := make(chan error)
			go func() {
				t.Log("worker running")
				// send an empty item (which is ignored) ensuring we've entered the select statement,
				// then close (a partial shutdown).
				ret <- nil
				t.Log("worker sent nothing")
				close(ret)
				t.Log("worker closed")
				// do the other half of the shutdown
				testBus.Publish(finalEvent)
				t.Log("worker published final event")
			}()
			return ret
		}

		signaler := func() <-chan os.Signal {
			return nil
		}

		ux := &uiMock{
			t:          t,
			finalEvent: finalEvent,
		}

		// ensure the mock sees at least the final event... note the event error is propagated
		ux.On("Handle", finalEvent).Return(finalEvent.Error)
		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(nil)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		// handle errors SHOULD propagate the event loop. We are additionally asserting that this case is
		// handled as a controlled shutdown (this test should not timeout)
		assert.ErrorIs(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
			finalEvent.Error,
			"should have seen a event error, but did not",
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func Test_eventLoop_signalsStopExecution(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		worker := func() <-chan error {
			// the worker will never return work and the event loop will always be waiting...
			return make(chan error)
		}

		signaler := func() <-chan os.Signal {
			ret := make(chan os.Signal)
			go func() {
				ret <- syscall.SIGINT
				// note: we do NOT close the channel to ensure the event loop does not depend on that behavior to exit
			}()
			return ret
		}

		ux := &uiMock{
			t: t,
		}

		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(nil)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		assert.NoError(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func Test_eventLoop_uiTeardownError(t *testing.T) {
	test := func(t *testing.T) {

		testBus := partybus.NewBus()
		subscription := testBus.Subscribe()
		t.Cleanup(testBus.Close)

		finalEvent := partybus.Event{
			Type: event.VulnerabilityScanningFinished,
		}

		worker := func() <-chan error {
			ret := make(chan error)
			go func() {
				t.Log("worker running")
				// send an empty item (which is ignored) ensuring we've entered the select statement,
				// then close (a partial shutdown).
				ret <- nil
				t.Log("worker sent nothing")
				close(ret)
				t.Log("worker closed")
				// do the other half of the shutdown
				testBus.Publish(finalEvent)
				t.Log("worker published final event")
			}()
			return ret
		}

		signaler := func() <-chan os.Signal {
			return nil
		}

		ux := &uiMock{
			t:          t,
			finalEvent: finalEvent,
		}

		teardownError := fmt.Errorf("sorry, dave, the UI doesn't want to be torn down")

		// ensure the mock sees at least the final event... note the event error is propagated
		ux.On("Handle", finalEvent).Return(nil)
		// ensure the mock sees basic setup/teardown events
		ux.On("Setup", mock.AnythingOfType("func() error")).Return(nil)
		ux.On("Teardown").Return(teardownError)

		var cleanupCalled bool
		cleanupFn := func() {
			t.Log("cleanup called")
			cleanupCalled = true
		}

		// ensure we see an error returned
		assert.ErrorIs(t,
			eventLoop(
				worker(),
				signaler(),
				subscription,
				cleanupFn,
				ux,
			),
			teardownError,
			"should have seen a UI teardown error, but did not",
		)

		assert.True(t, cleanupCalled, "cleanup function not called")
		ux.AssertExpectations(t)
	}

	// if there is a bug, then there is a risk of the event loop never returning
	testWithTimeout(t, 5*time.Second, test)
}

func testWithTimeout(t *testing.T, timeout time.Duration, test func(*testing.T)) {
	done := make(chan bool)
	go func() {
		test(t)
		done <- true
	}()

	select {
	case <-time.After(timeout):
		t.Fatal("test timed out")
	case <-done:
	}
}
