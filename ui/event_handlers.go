package ui

import (
	"context"
	"fmt"
	"io"
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
	return []progress.Monitorable{
		m.PackagesProcessed,
		m.VulnerabilitiesDiscovered,
		m.VulnerabilitiesCategories.Unknown,
		m.VulnerabilitiesCategories.Low,
		m.VulnerabilitiesCategories.Medium,
		m.VulnerabilitiesCategories.High,
		m.VulnerabilitiesCategories.Critical,
		m.VulnerabilitiesCategories.Fixed,
	}
}

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

	summaryTempl := "%d critical, %d high, %d medium, %d low  %s"
	FixTempl := "%d fixed"

	formatFn := func(total, unknown, low, medium, high, critical, fixed int64) {
		spin := color.Magenta.Sprint(spinner.Next())
		auxInfo := auxInfoFormat.Sprintf("[vulnerabilities %d]", total)
		_, _ = io.WriteString(scanningLine, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))

		unknownStr := ""
		if unknown > 0 {
			unknownStr = fmt.Sprintf("(%d unknown)", unknown)
		}

		status := fmt.Sprintf(summaryTempl, critical, high, medium, low, unknownStr)
		_, _ = io.WriteString(summaryLine, auxInfoFormat.Sprintf("   %s %s", branch, status))

		fixStatus := fmt.Sprintf(FixTempl, fixed)
		_, _ = io.WriteString(fixLine, auxInfoFormat.Sprintf("   %s %s", end, fixStatus))
	}

	go func() {
		defer wg.Done()

		formatFn(0, 0, 0, 0, 0, 0, 0)
		for p := range stream {
			formatFn(p[1], p[2], p[3], p[4], p[5], p[6], p[7])
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Scanned image")
		auxInfo := auxInfoFormat.Sprintf("[%d vulnerabilities]", monitor.VulnerabilitiesDiscovered.Current())
		_, _ = io.WriteString(scanningLine, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))

		unknownStr := ""
		unknown := monitor.VulnerabilitiesCategories.Unknown.Current()
		if unknown > 0 {
			unknownStr = fmt.Sprintf("(%d unknown)", unknown)
		}

		status := fmt.Sprintf(
			summaryTempl,
			monitor.VulnerabilitiesCategories.Critical.Current(),
			monitor.VulnerabilitiesCategories.High.Current(),
			monitor.VulnerabilitiesCategories.Medium.Current(),
			monitor.VulnerabilitiesCategories.Low.Current(),
			unknownStr,
		)
		auxInfo2 := auxInfoFormat.Sprintf("   %s %s", branch, status)
		_, _ = io.WriteString(summaryLine, auxInfo2)

		fixStatus := fmt.Sprintf(
			FixTempl,
			monitor.VulnerabilitiesCategories.Fixed.Current(),
		)
		_, _ = io.WriteString(fixLine, auxInfoFormat.Sprintf("   %s %s", end, fixStatus))
	}()

	return nil
}

func (r *Handler) VerifyAttestationSignature(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		spin := color.Green.Sprint(completedStatus)
		title := tileFormat.Sprint("Attestation verified")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, ""))
	}()

	return nil
}

func (r *Handler) SkippedAttestationVerification(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		spin := color.Green.Sprint(completedStatus)
		title := tileFormat.Sprint("Skipped attestation verification")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, ""))
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
