package ui

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/wagoodman/go-progress/format"
	"github.com/wagoodman/jotframe/pkg/frame"

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/ui/components"
	syftUI "github.com/anchore/syft/ui"
)

const maxBarWidth = 50
const statusSet = components.SpinnerDotSet // SpinnerCircleOutlineSet
const completedStatus = "✔"                // "●"
const tileFormat = color.Bold

var (
	auxInfoFormat       = color.HEX("#777777")
	statusTitleTemplate = fmt.Sprintf(" %%s %%-%ds ", syftUI.StatusTitleColumn)
)

func startProcess() (format.Simple, *components.Spinner) {
	width, _ := frame.GetTerminalSize()
	barWidth := int(0.25 * float64(width))
	if barWidth > maxBarWidth {
		barWidth = maxBarWidth
	}
	formatter := format.NewSimpleWithTheme(barWidth, format.HeavyNoBarTheme, format.ColorCompleted, format.ColorTodo)
	spinner := components.NewSpinner(statusSet)

	return formatter, &spinner
}

func (r *Handler) UpdateVulnerabilityDatabaseHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	prog, err := grypeEventParsers.ParseUpdateVulnerabilityDatabase(event)
	if err != nil {
		return fmt.Errorf("bad FetchImage event: %w", err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	wg.Add(1)

	formatter, spinner := startProcess()
	stream := progress.Stream(ctx, prog, 150*time.Millisecond)
	title := tileFormat.Sprint("Vulnerability DB")

	formatFn := func(p progress.Progress) {
		progStr, err := formatter.Format(p)
		spin := color.Magenta.Sprint(spinner.Next())
		if err != nil {
			_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
		} else {
			var auxInfo string
			switch prog.Stage() {
			case "downloading":
				progStr += " "
				auxInfo = auxInfoFormat.Sprintf(" [%s / %s]", humanize.Bytes(uint64(prog.Current())), humanize.Bytes(uint64(prog.Size())))
			default:
				progStr = ""
				auxInfo = auxInfoFormat.Sprintf("[%s]", prog.Stage())
			}

			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s%s", spin, title, progStr, auxInfo))
		}
	}

	go func() {
		defer wg.Done()

		formatFn(progress.Progress{})
		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Vulnerability DB")
		auxInfo := auxInfoFormat.Sprintf("[%s]", prog.Stage())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()
	return err
}

func scanningAndSummaryLines(fr *frame.Frame) (scanningLine, summaryLine, fixedLine *frame.Line, err error) {
	scanningLine, err = fr.Append()
	if err != nil {
		return nil, nil, nil, err
	}

	summaryLine, err = fr.Append()
	if err != nil {
		return nil, nil, nil, err
	}

	fixedLine, err = fr.Append()
	if err != nil {
		return nil, nil, nil, err
	}
	return scanningLine, summaryLine, fixedLine, nil
}

func assembleProgressMonitors(m *matcher.Monitor) []progress.Monitorable {
	ret := []progress.Monitorable{
		m.PackagesProcessed,
		m.VulnerabilitiesDiscovered,
	}

	allSeverities := append([]vulnerability.Severity{vulnerability.UnknownSeverity}, vulnerability.AllSeverities()...)
	for _, sev := range allSeverities {
		ret = append(ret, m.BySeverity[sev])
	}

	ret = append(ret, m.Fixed)

	return ret
}

//nolint:funlen
func (r *Handler) VulnerabilityScanningStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	monitor, err := grypeEventParsers.ParseVulnerabilityScanningStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	scanningLine, summaryLine, fixLine, err := scanningAndSummaryLines(fr)
	if err != nil {
		return err
	}

	wg.Add(1)

	monitors := assembleProgressMonitors(monitor)

	_, spinner := startProcess()
	stream := progress.StreamMonitors(ctx, monitors, 50*time.Millisecond)

	title := tileFormat.Sprint("Scanning image...")
	branch := "├──"
	end := "└──"

	fixTempl := "%d fixed"

	formatFn := func(m *matcher.Monitor, complete bool) {
		var spin string
		if complete {
			spin = color.Green.Sprint(completedStatus)
		} else {
			spin = color.Magenta.Sprint(spinner.Next())
		}

		auxInfo := auxInfoFormat.Sprintf("[%d vulnerabilities]", m.VulnerabilitiesDiscovered.Current())
		_, _ = io.WriteString(scanningLine, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))

		var unknownStr string
		unknown := m.BySeverity[vulnerability.UnknownSeverity].Current()
		if unknown > 0 {
			unknownStr = fmt.Sprintf(" (%d unknown)", unknown)
		}

		allSeverities := vulnerability.AllSeverities()
		sort.Sort(sort.Reverse(vulnerability.Severities(allSeverities)))

		var builder strings.Builder
		for idx, sev := range allSeverities {
			count := m.BySeverity[sev].Current()
			builder.WriteString(fmt.Sprintf("%d %s", count, sev))
			if idx < len(allSeverities)-1 {
				builder.WriteString(", ")
			}
		}
		builder.WriteString(unknownStr)

		status := builder.String()
		auxInfo2 := auxInfoFormat.Sprintf("   %s %s", branch, status)
		_, _ = io.WriteString(summaryLine, auxInfo2)

		fixStatus := fmt.Sprintf(fixTempl, m.Fixed.Current())
		_, _ = io.WriteString(fixLine, auxInfoFormat.Sprintf("   %s %s", end, fixStatus))
	}

	go func() {
		defer wg.Done()

		formatFn(monitor, false)
		for range stream {
			formatFn(monitor, false)
		}
		formatFn(monitor, true)
	}()

	return nil
}

func (r *Handler) DatabaseDiffingStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	monitor, err := grypeEventParsers.ParseDatabaseDiffingStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	_, spinner := startProcess()
	stream := progress.StreamMonitors(ctx, []progress.Monitorable{monitor.RowsProcessed, monitor.DifferencesDiscovered}, 50*time.Millisecond)
	title := tileFormat.Sprint("Diffing databases...")

	formatFn := func(val int64) {
		spin := color.Magenta.Sprint(spinner.Next())
		auxInfo := auxInfoFormat.Sprintf("[differences %d]", val)
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}

	go func() {
		defer wg.Done()

		formatFn(0)
		for p := range stream {
			formatFn(p[1])
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Diff Complete")
		auxInfo := auxInfoFormat.Sprintf("[%d differences]", monitor.DifferencesDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()

	return nil
}
