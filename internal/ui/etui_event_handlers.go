//go:build linux || darwin
// +build linux darwin

package ui

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	griffonEventParsers "github.com/nextlinux/griffon/griffon/event/parsers"
	"github.com/nextlinux/griffon/internal"
	"github.com/nextlinux/griffon/internal/version"
)

func handleAppUpdateAvailable(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := griffonEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New version of %s is available: %s (currently running: %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)
	_, _ = io.WriteString(line, message)

	return nil
}
