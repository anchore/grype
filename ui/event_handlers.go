package ui

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/internal/ui/common"
	"github.com/dustin/go-humanize"
	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
	"github.com/wagoodman/go-progress/format"
	"github.com/wagoodman/jotframe/pkg/frame"
)

const maxBarWidth = 50
const statusSet = common.SpinnerDotSet // SpinnerCircleOutlineSet
const completedStatus = "✔"            // "●"
const tileFormat = color.Bold
const statusTitleTemplate = " %s %-28s "

var auxInfoFormat = color.HEX("#777777")

func startProcess() (format.Simple, *common.Spinner) {
	width, _ := frame.GetTerminalSize()
	barWidth := int(0.25 * float64(width))
	if barWidth > maxBarWidth {
		barWidth = maxBarWidth
	}
	formatter := format.NewSimpleWithTheme(barWidth, format.HeavyNoBarTheme, format.ColorCompleted, format.ColorTodo)
	spinner := common.NewSpinner(statusSet)

	return formatter, &spinner
}

func DownloadingVulnerabilityDatabaseHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	_, prog, err := grypeEventParsers.ParseUpdateVulnerabilityDatabase(event)
	if err != nil {
		return fmt.Errorf("bad FetchImage event: %w", err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	wg.Add(1)

	go func() {
		defer line.Close()
		defer wg.Done()
		formatter, spinner := startProcess()
		stream := progress.Stream(ctx, prog, 150*time.Millisecond)
		title := tileFormat.Sprint("Updating Vulnerability DB...")

		formatFn := func(p progress.Progress) {
			progStr, err := formatter.Format(p)
			spin := color.Magenta.Sprint(spinner.Next())
			if err != nil {
				_, _ = io.WriteString(line, fmt.Sprintf("Error: %+v", err))
			} else {
				var auxInfo string
				switch prog.Stage() {
				case "downloading":
					auxInfo = auxInfoFormat.Sprintf("[%s / %s]", humanize.Bytes(uint64(prog.Current())), humanize.Bytes(uint64(prog.Size())))
				default:
					auxInfo = auxInfoFormat.Sprintf("[%s]", prog.Stage())
				}

				_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s %s", spin, title, progStr, auxInfo))
			}
		}

		formatFn(progress.Progress{})

		for p := range stream {
			formatFn(p)
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Updated Vulnerability DB")
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate, spin, title))
	}()
	return err
}

func VulnerabilityScanningStartedHandler(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	monitor, err := grypeEventParsers.ParseVulnerabilityScanningStarted(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}

	wg.Add(1)

	go func() {
		defer line.Close()
		defer wg.Done()
		_, spinner := startProcess()
		stream := progress.StreamMonitors(ctx, []progress.Monitorable{monitor.PackagesProcessed, monitor.VulnerabilitiesDiscovered}, 50*time.Millisecond)
		title := tileFormat.Sprint("Scanning image...")

		formatFn := func(val int64) {
			spin := color.Magenta.Sprint(spinner.Next())
			auxInfo := auxInfoFormat.Sprintf("[vulnerabilities %d]", val)
			_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
		}

		formatFn(0)
		for p := range stream {
			formatFn(p[1])
		}

		spin := color.Green.Sprint(completedStatus)
		title = tileFormat.Sprint("Scanned image")
		auxInfo := auxInfoFormat.Sprintf("[%d vulnerabilities]", monitor.VulnerabilitiesDiscovered.Current())
		_, _ = io.WriteString(line, fmt.Sprintf(statusTitleTemplate+"%s", spin, title, auxInfo))
	}()

	return nil
}
