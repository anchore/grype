package ui

import (
	"bytes"
	"testing"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/grype/event/parsers"
)

func Test_postUIEventWriter_write(t *testing.T) {

	tests := []struct {
		name    string
		quiet   bool
		events  []partybus.Event
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "no events",
		},
		{
			name: "all events",
			events: []partybus.Event{
				{
					Type:  event.CLINotification,
					Value: "\n\n<my notification 1!!\n...still notifying>\n\n",
				},
				{
					Type:  event.CLINotification,
					Value: "<notification 2>",
				},
				{
					Type: event.CLIAppUpdateAvailable,
					Value: parsers.UpdateCheck{
						New:     "v0.33.0",
						Current: "[not provided]",
					},
				},
				{
					Type:  event.CLINotification,
					Value: "<notification 3>",
				},
				{
					Type:  event.CLIReport,
					Value: "\n\n<my --\n-\n-\nreport 1!!>\n\n",
				},
				{
					Type:  event.CLIReport,
					Value: "<report 2>",
				},
			},
		},
		{
			name:  "quiet only shows report",
			quiet: true,
			events: []partybus.Event{

				{
					Type:  event.CLINotification,
					Value: "<notification 1>",
				},
				{
					Type: event.CLIAppUpdateAvailable,
					Value: parsers.UpdateCheck{
						New:     "<new version>",
						Current: "<current version>",
					},
				},
				{
					Type:  event.CLIReport,
					Value: "<report 1>",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}
			w := newPostUIEventWriter(stdout, stderr)

			tt.wantErr(t, w.write(tt.quiet, tt.events...))

			t.Run("stdout", func(t *testing.T) {
				snaps.MatchSnapshot(t, stdout.String())
			})

			t.Run("stderr", func(t *testing.T) {
				snaps.MatchSnapshot(t, stderr.String())
			})
		})
	}
}
