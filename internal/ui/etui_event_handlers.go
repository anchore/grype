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

	grypeEventParsers "github.com/anchore/grype/grype/event/parsers"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
)

func handleAppUpdateAvailable(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := grypeEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New version of %s available: %s (current version is %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)
	_, _ = io.WriteString(line, message)

	return nil
}
