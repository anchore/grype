package distro

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/grype/grype/version"
)

func TestDefaultFixChannels(t *testing.T) {
	channels := DefaultFixChannels()

	// this seems like a silly test, however, it is critical to ensure that the default channels have EUS with expected values
	expected := FixChannels{
		{
			Name:     "eus",
			IDs:      []string{"rhel"},
			Apply:    ChannelConditionallyEnabled,
			Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
		},
	}

	if diff := cmp.Diff(expected, channels); diff != "" {
		t.Errorf("DefaultFixChannels() mismatch (-want +got):\n%s", diff)
	}
}

func TestFixChannels_Apply(t *testing.T) {
	tests := []struct {
		name     string
		channels FixChannels
		enable   FixChannelEnabled
		want     FixChannels
	}{
		{
			name: "apply always enabled to single channel",
			channels: FixChannels{
				{
					Name:  "eus",
					Apply: ChannelConditionallyEnabled,
				},
			},
			enable: ChannelAlwaysEnabled,
			want: FixChannels{
				{
					Name:  "eus",
					Apply: ChannelAlwaysEnabled,
				},
			},
		},
		{
			name: "apply never enabled to multiple channels",
			channels: FixChannels{
				{
					Name:  "eus",
					Apply: ChannelConditionallyEnabled,
				},
				{
					Name:  "main",
					Apply: ChannelAlwaysEnabled,
				},
			},
			enable: ChannelNeverEnabled,
			want: FixChannels{
				{
					Name:  "eus",
					Apply: ChannelNeverEnabled,
				},
				{
					Name:  "main",
					Apply: ChannelNeverEnabled,
				},
			},
		},
		{
			name:     "apply to empty channels",
			channels: FixChannels{},
			enable:   ChannelAlwaysEnabled,
			want:     FixChannels{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.channels.Apply(tt.enable)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FixChannels.Apply() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFixChannels_Get(t *testing.T) {
	channels := FixChannels{
		{
			Name:  "eus",
			IDs:   []string{"rhel"},
			Apply: ChannelConditionallyEnabled,
		},
		{
			Name:  "main",
			IDs:   []string{"debian", "ubuntu"},
			Apply: ChannelAlwaysEnabled,
		},
	}

	tests := []struct {
		name        string
		channelName string
		want        *FixChannel
	}{
		{
			name:        "find existing channel by exact name",
			channelName: "eus",
			want: &FixChannel{
				Name:  "eus",
				IDs:   []string{"rhel"},
				Apply: ChannelConditionallyEnabled,
			},
		},
		{
			name:        "find existing channel by case insensitive name",
			channelName: "EUS",
			want: &FixChannel{
				Name:  "eus",
				IDs:   []string{"rhel"},
				Apply: ChannelConditionallyEnabled,
			},
		},
		{
			name:        "find existing channel by mixed case name",
			channelName: "Main",
			want: &FixChannel{
				Name:  "main",
				IDs:   []string{"debian", "ubuntu"},
				Apply: ChannelAlwaysEnabled,
			},
		},
		{
			name:        "channel not found",
			channelName: "nonexistent",
			want:        nil,
		},
		{
			name:        "empty channel name",
			channelName: "",
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := channels.Get(tt.channelName)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FixChannels.Get() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
