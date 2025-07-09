package distro

import (
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/linux"
)

type FixChannelEnabled string

const (
	// ChannelNeverEnabled means that the channel should never be applied to the distro
	ChannelNeverEnabled FixChannelEnabled = "never"

	// ChannelAlwaysEnabled means that the channel should always be applied to the distro
	ChannelAlwaysEnabled FixChannelEnabled = "always"

	// ChannelConditionallyEnabled means that the channel should conditionally be applied to the distro if there is SBOM material that indicates the channel was configured at build time
	ChannelConditionallyEnabled FixChannelEnabled = "auto"
)

// FixChannel represents a subscription or repository where package fixes and updates are provided for a Linux distribution
type FixChannel struct {
	// Name is the name of the channel, e.g. "eus" for RHEL
	Name string

	// IDs is a list of distro release IDs that this channel applies to, e.g. "rhel" for RHEL (this is relative to the /etc/os-release ID field)
	IDs []string

	// Apply indicates how the channel should be applied to the distrp
	Apply FixChannelEnabled

	// Versions is a version constraint that indicates which versions of the distro this channel applies to (e.g. ">= 8.0" for RHEL 8 and above)
	Versions version.Constraint
}

type FixChannels []FixChannel

func DefaultFixChannels() FixChannels {
	return []FixChannel{
		{
			Name:     "eus",
			IDs:      []string{"rhel"},
			Apply:    ChannelNeverEnabled, // this will change to ChannelConditionallyEnabled once there is data in the DB to support it
			Versions: version.MustGetConstraint(">= 8.0", version.SemanticFormat),
		},
	}
}

func (f FixChannels) Apply(enable FixChannelEnabled) FixChannels {
	for i := range f {
		f[i].Apply = enable
	}
	return f
}

func applyChannels(release linux.Release, ver *version.Version, existingChannels []string, channels []FixChannel) []string {
	existingChannelSet := strset.New(existingChannels...)
	var result []string

	addResult := func(channel string, extendedSupport bool, pref FixChannelEnabled) {
		res := applyChannel(channel, extendedSupport, pref)
		if res != "" {
			result = append(result, res)
		}
	}

	for _, channel := range channels {
		var found bool
		for _, channelID := range channel.IDs {
			if release.ID == channelID {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// we will either get a direct indication as a flag, or as a result of the channel being applied to the distro already
		extendedSupport := release.ExtendedSupport || existingChannelSet.Has(channel.Name)

		if ver == nil && release.VersionCodename != "" {
			// TODO: there is not a good way to do this without a DB call, so for now we will assume the channel applies
			log.Debugf("using channel %q for distro %q with codename %q", channel.Name, release.ID, release.VersionCodename)

			addResult(channel.Name, extendedSupport, channel.Apply)
			continue
		}

		if channel.Versions != nil && ver != nil {
			isApplicable, err := channel.Versions.Satisfied(ver)
			if err != nil {
				log.WithFields("error", err, "constraint", channel.Versions).Debugf("unable to determine if channel %q is applicable for distro %q with version %q", channel.Name, release.ID, ver)
				continue
			}
			if isApplicable {
				log.Debugf("using channel %q for distro %q with version %q", channel.Name, release.ID, ver)
				addResult(channel.Name, extendedSupport, channel.Apply)
				continue
			}
		}
		log.Debugf("using channel %q for distro %q", channel.Name, release.ID)
		addResult(channel.Name, extendedSupport, channel.Apply)
	}
	return result
}

func applyChannel(channel string, hintsExtendedSupport bool, pref FixChannelEnabled) string {
	switch pref {
	case ChannelNeverEnabled:
		return ""
	case ChannelAlwaysEnabled:
		return channel
	case ChannelConditionallyEnabled:
		if hintsExtendedSupport {
			return channel
		}
	}
	return ""
}
