package distro

type FixChannelEnabled string

const (
	// ChannelNeverEnabled means that the channel should never be applied to the distro
	ChannelNeverEnabled FixChannelEnabled = "never"

	// ChannelAlwaysEnabled means that the channel should always be applied to the distro
	ChannelAlwaysEnabled FixChannelEnabled = "always"

	// ChannelConditionallyEnabled means that the channel should conditionally be applied to the distro if there is SBOM material that indicates the channel was configured at build time
	ChannelConditionallyEnabled FixChannelEnabled = "auto"
)

type FixChannel struct {
	Name  string
	IDs   []string
	Apply FixChannelEnabled
}

func DefaultFixChannels() []FixChannel {
	return []FixChannel{
		{
			Name:  "eus",
			IDs:   []string{"rhel"},
			Apply: ChannelConditionallyEnabled,
		},
	}
}
