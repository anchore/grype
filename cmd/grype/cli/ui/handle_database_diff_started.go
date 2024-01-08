package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/grype/grype/event/monitor"
	"github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/internal/log"
)

type dbDiffProgressStager struct {
	monitor *monitor.DBDiff
}

func (p dbDiffProgressStager) Stage() string {
	if progress.IsErrCompleted(p.monitor.StageProgress.Error()) {
		return fmt.Sprintf("%d differences found", p.monitor.DifferencesDiscovered.Current())
	}
	return p.monitor.Stager.Stage()
}

func (p dbDiffProgressStager) Current() int64 {
	return p.monitor.StageProgress.Current()
}

func (p dbDiffProgressStager) Error() error {
	return p.monitor.StageProgress.Error()
}

func (p dbDiffProgressStager) Size() int64 {
	return p.monitor.StageProgress.Size()
}

func (m *Handler) handleDatabaseDiffStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	mon, err := parsers.ParseDatabaseDiffingStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Compare Vulnerability DBs",
			Running: "Comparing Vulnerability DBs",
			Success: "Compared Vulnerability DBs",
		},
		taskprogress.WithStagedProgressable(dbDiffProgressStager{monitor: mon}),
	)

	tsk.HideStageOnSuccess = false

	return []tea.Model{tsk}, nil
}
