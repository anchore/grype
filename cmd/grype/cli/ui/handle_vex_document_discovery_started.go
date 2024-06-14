package ui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/dustin/go-humanize"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/internal/log"
)

type vexDocumentDiscoveryStager struct {
	prog progress.StagedProgressable
}

func (s vexDocumentDiscoveryStager) Stage() string {
	stage := s.prog.Stage()
	if stage == "downloading" {
		// note: since validation is baked into the download progress there is no visibility into this stage.
		// for that reason we report "validating" on the last byte being downloaded (which tends to be the longest
		// since go-downloader is doing this work).
		if s.prog.Current() >= s.prog.Size()-1 {
			return "validating"
		}
		// show intermediate progress of the download
		return fmt.Sprintf("%s / %s", humanize.Bytes(uint64(s.prog.Current())), humanize.Bytes(uint64(s.prog.Size())))
	}
	return stage
}

func (m *Handler) handleVexDocumentDiscoveryStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	prog, err := parsers.ParseVexDocumentDiscoveryStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Search for VEX Documents",
			Running: "Searching for VEX Documents",
			Success: "Searched for VEX Documents",
		},
		taskprogress.WithStagedProgressable(prog), // ignore the static stage provided by the event
		taskprogress.WithStager(vexDocumentDiscoveryStager{prog: prog}),
	)

	tsk.HideStageOnSuccess = false

	return []tea.Model{tsk}, tsk.Init()
}
