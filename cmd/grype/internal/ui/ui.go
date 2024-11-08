package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly"
	"github.com/anchore/bubbly/bubbles/frame"
	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

var _ interface {
	tea.Model
	partybus.Responder
	clio.UI
} = (*UI)(nil)

type UI struct {
	program        *tea.Program
	running        *sync.WaitGroup
	quiet          bool
	subscription   partybus.Unsubscribable
	finalizeEvents []partybus.Event

	handler *bubbly.HandlerCollection
	frame   tea.Model
}

func New(quiet bool, handlers ...bubbly.EventHandler) *UI {
	return &UI{
		handler: bubbly.NewHandlerCollection(handlers...),
		frame:   frame.New(),
		running: &sync.WaitGroup{},
		quiet:   quiet,
	}
}

func (m *UI) Setup(subscription partybus.Unsubscribable) error {
	// we still want to collect log messages, however, we also the logger shouldn't write to the screen directly
	if logWrapper, ok := log.Get().(logger.Controller); ok {
		logWrapper.SetOutput(m.frame.(*frame.Frame).Footer())
	}

	m.subscription = subscription
	m.program = tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin))
	m.running.Add(1)

	go func() {
		defer m.running.Done()
		if _, err := m.program.Run(); err != nil {
			log.Errorf("unable to start UI: %+v", err)
			bus.ExitWithInterrupt()
		}
	}()

	return nil
}

func (m *UI) Handle(e partybus.Event) error {
	if m.program != nil {
		m.program.Send(e)
	}
	return nil
}

func (m *UI) Teardown(force bool) error {
	defer func() {
		// allow for traditional logging to resume now that the UI is shutting down
		if logWrapper, ok := log.Get().(logger.Controller); ok {
			logWrapper.SetOutput(os.Stderr)
		}
	}()

	if !force {
		m.handler.Wait()
		m.program.Quit()
		// typically in all cases we would want to wait for the UI to finish. However there are still error cases
		// that are not accounted for, resulting in hangs. For now, we'll just wait for the UI to finish in the
		// happy path only. There will always be an indication of the problem to the user via reporting the error
		// string from the worker (outside of the UI after teardown).
		m.running.Wait()
	} else {
		_ = runWithTimeout(250*time.Millisecond, func() error {
			m.handler.Wait()
			return nil
		})

		// it may be tempting to use Kill() however it has been found that this can cause the terminal to be left in
		// a bad state (where Ctrl+C and other control characters no longer works for future processes in that terminal).
		m.program.Quit()

		_ = runWithTimeout(250*time.Millisecond, func() error {
			m.running.Wait()
			return nil
		})
	}

	// TODO: allow for writing out the full log output to the screen (only a partial log is shown currently)
	// this needs coordination to know what the last frame event is to change the state accordingly (which isn't possible now)

	return newPostUIEventWriter(os.Stdout, os.Stderr).write(m.quiet, m.finalizeEvents...)
}

// bubbletea.Model functions

func (m UI) Init() tea.Cmd {
	return m.frame.Init()
}

func (m UI) RespondsTo() []partybus.EventType {
	return append([]partybus.EventType{
		event.CLIReport,
		event.CLINotification,
		event.CLIAppUpdateAvailable,
	}, m.handler.RespondsTo()...)
}

func (m *UI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// note: we need a pointer receiver such that the same instance of UI used in Teardown is referenced (to keep finalize events)

	var cmds []tea.Cmd

	// allow for non-partybus UI updates (such as window size events). Note: these must not affect existing models,
	// that is the responsibility of the frame object on this UI object. The handler is a factory of models
	// which the frame is responsible for the lifecycle of. This update allows for injecting the initial state
	// of the world when creating those models.
	m.handler.OnMessage(msg)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		// today we treat esc and ctrl+c the same, but in the future when the worker has a graceful way to
		// cancel in-flight work via a context, we can wire up esc to this path with bus.Exit()
		case "esc", "ctrl+c":
			bus.ExitWithInterrupt()
			return m, tea.Quit
		}

	case partybus.Event:
		log.WithFields("component", "ui").Tracef("event: %q", msg.Type)

		switch msg.Type {
		case event.CLIReport, event.CLINotification, event.CLIAppUpdateAvailable:
			// keep these for when the UI is terminated to show to the screen (or perform other events)
			m.finalizeEvents = append(m.finalizeEvents, msg)

			// why not return tea.Quit here for exit events? because there may be UI components that still need the update-render loop.
			// for this reason we'll let the event loop call Teardown() which will explicitly wait for these components
			return m, nil
		}

		models, cmd := m.handler.Handle(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		for _, newModel := range models {
			if newModel == nil {
				continue
			}
			cmds = append(cmds, newModel.Init())
			m.frame.(*frame.Frame).AppendModel(newModel)
		}
		// intentionally fallthrough to update the frame model
	}

	frameModel, cmd := m.frame.Update(msg)
	m.frame = frameModel
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m UI) View() string {
	return m.frame.View()
}

func runWithTimeout(timeout time.Duration, fn func() error) (err error) {
	c := make(chan struct{}, 1)
	go func() {
		err = fn()
		c <- struct{}{}
	}()
	select {
	case <-c:
	case <-time.After(timeout):
		return fmt.Errorf("timed out after %v", timeout)
	}
	return err
}
