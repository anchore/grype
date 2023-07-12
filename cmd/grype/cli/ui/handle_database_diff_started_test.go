package ui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/event/monitor"
)

func TestHandler_handleDatabaseDiffStarted(t *testing.T) {

	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "DB diff started",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(50)

				diffs := &progress.Manual{}
				diffs.Set(20)

				mon := monitor.DBDiff{
					Stager:                &progress.Stage{Current: "current"},
					StageProgress:         prog,
					DifferencesDiscovered: diffs,
				}

				return partybus.Event{
					Type:  event.DatabaseDiffingStarted,
					Value: mon,
				}
			},
		},
		{
			name: "DB diff complete",
			eventFn: func(t *testing.T) partybus.Event {
				prog := &progress.Manual{}
				prog.SetTotal(100)
				prog.Set(100)
				prog.SetCompleted()

				diffs := &progress.Manual{}
				diffs.Set(20)

				mon := monitor.DBDiff{
					Stager:                &progress.Stage{Current: "current"},
					StageProgress:         prog,
					DifferencesDiscovered: diffs,
				}

				return partybus.Event{
					Type:  event.DatabaseDiffingStarted,
					Value: mon,
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.eventFn(t)
			handler := New(DefaultHandlerConfig())
			handler.WindowSize = tea.WindowSizeMsg{
				Width:  100,
				Height: 80,
			}

			models := handler.Handle(e)
			require.Len(t, models, 1)
			model := models[0]

			tsk, ok := model.(taskprogress.Model)
			require.True(t, ok)

			got := runModel(t, tsk, tt.iterations, taskprogress.TickMsg{
				Time:     time.Now(),
				Sequence: tsk.Sequence(),
				ID:       tsk.ID(),
			})
			t.Log(got)
			snaps.MatchSnapshot(t, got)
		})
	}
}
