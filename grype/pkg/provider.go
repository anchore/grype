package pkg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	applyChannel := getDistroChannelApplier(config.Distro.FixChannels)
	if config.Distro.Override != nil {
		applyChannel(config.Distro.Override)
		log.Infof("using distro: %s", config.Distro.Override.String())
	}

	packages, ctx, s, err := provide(userInput, config, applyChannel)
	if err != nil {
		return nil, Context{}, nil, err
	}
	setContextDistro(packages, &ctx)

	// set the distro on each package if there is not already one set
	if ctx.Distro != nil {
		for i := range packages {
			if packages[i].Distro == nil {
				packages[i].Distro = ctx.Distro
			}
		}

		if config.Distro.Override == nil {
			log.Infof("using distro: %s", ctx.Distro.String())
		}
	}

	return packages, ctx, s, nil
}

// buildChannelIndex creates a map of distro IDs to their applicable fix channels
func buildChannelIndex(channels []distro.FixChannel) map[string]distro.FixChannels {
	idx := make(map[string]distro.FixChannels, len(channels))
	for _, c := range channels {
		if c.Name == "" {
			continue
		}
		for _, id := range c.IDs {
			if id == "" {
				continue
			}
			id = strings.ToLower(id)
			idx[id] = append(idx[id], c)
		}
	}
	return idx
}

func getDistroChannelApplier(channels []distro.FixChannel) func(d *distro.Distro) bool {
	idx := buildChannelIndex(channels)

	return func(d *distro.Distro) bool {
		if d == nil {
			return false
		}

		id := strings.ToLower(d.ID())
		channels, ok := idx[id]
		if !ok {
			return false
		}

		return applyChannelsToDistro(d, channels)
	}
}

// applyChannelsToDistro applies fix channels to a distro based on channel configuration
func applyChannelsToDistro(d *distro.Distro, channels distro.FixChannels) bool {
	var result []string
	existing := strset.New(d.Channels...)
	ver := version.New(d.Version, version.SemanticFormat)

	shouldReview := func(channel distro.FixChannel) bool {
		if channel.Versions != nil && ver != nil {
			isApplicable, err := channel.Versions.Satisfied(ver)
			if err != nil {
				log.WithFields("error", err, "constraint", channel.Versions).Debugf("unable to determine if channel %q is applicable for distro %q with version %q", channel.Name, d.Type, ver)
				return true
			}
			return isApplicable
		}
		return true
	}

	var modified bool
	for _, channel := range channels {
		if channel.Name == "" {
			continue
		}

		if !shouldReview(channel) {
			log.WithFields("channel", channel.Name, "distro", d.Type, "version", ver).Debugf("skipping channel %q for distro %q with version %q", channel.Name, d.Type, ver)
			continue
		}

		switch channel.Apply {
		case distro.ChannelNeverEnabled:
			if existing.Has(channel.Name) {
				modified = true
			}
		case distro.ChannelAlwaysEnabled:
			result = append(result, channel.Name)
			if !existing.Has(channel.Name) {
				modified = true
			}
		case distro.ChannelConditionallyEnabled:
			if existing.Has(channel.Name) {
				result = append(result, channel.Name)
			}
		}
	}

	d.Channels = result
	return modified
}

// Provide a set of packages and context metadata describing where they were sourced from.
func provide(userInput string, config ProviderConfig, applyChannel func(d *distro.Distro) bool) ([]Package, Context, *sbom.SBOM, error) {
	packages, ctx, s, err := purlProvider(userInput, config, applyChannel)
	if !errors.Is(err, errDoesNotProvide) {
		log.WithFields("input", userInput).Trace("interpreting input as one or more PURLs")
		return packages, ctx, s, err
	}

	packages, ctx, s, err = cpeProvider(userInput, config)
	if !errors.Is(err, errDoesNotProvide) {
		log.WithFields("input", userInput).Trace("interpreting input as a one or more CPEs")
		return packages, ctx, s, err
	}

	packages, ctx, s, err = syftSBOMProvider(userInput, config, applyChannel)
	if !errors.Is(err, errDoesNotProvide) {
		if len(config.Exclusions) > 0 {
			var exclusionsErr error
			packages, exclusionsErr = filterPackageExclusions(packages, config.Exclusions)
			if exclusionsErr != nil {
				return nil, ctx, s, exclusionsErr
			}
		}
		log.WithFields("input", userInput).Trace("interpreting input as an SBOM document")
		return packages, ctx, s, err
	}

	log.WithFields("input", userInput).Trace("passing input to syft for interpretation")
	return syftProvider(userInput, config, applyChannel)
}

// This will filter the provided packages list based on a set of exclusion expressions. Globs
// are allowed for the exclusions. A package will be *excluded* only if *all locations* match
// one of the provided exclusions.
func filterPackageExclusions(packages []Package, exclusions []string) ([]Package, error) {
	var out []Package
	for _, pkg := range packages {
		includePackage := true
		locations := pkg.Locations.ToSlice()
		if len(locations) > 0 {
			includePackage = false
			// require ALL locations to be excluded for the package to be excluded
		location:
			for _, location := range locations {
				for _, exclusion := range exclusions {
					match, err := locationMatches(location, exclusion)
					if err != nil {
						return nil, err
					}
					if match {
						continue location
					}
				}
				// if this point is reached, one location has not matched any exclusion, include the package
				includePackage = true
				break
			}
		}
		if includePackage {
			out = append(out, pkg)
		}
	}
	return out, nil
}

// Test a location RealPath and VirtualPath for a match against the exclusion parameter.
// The exclusion allows glob expressions such as `/usr/**` or `**/*.json`. If the exclusion
// is an invalid pattern, an error is returned; otherwise, the resulting boolean indicates a match.
func locationMatches(location file.Location, exclusion string) (bool, error) {
	matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
	if err != nil {
		return false, err
	}
	matchesVirtualPath, err := doublestar.Match(exclusion, location.AccessPath)
	if err != nil {
		return false, err
	}
	return matchesRealPath || matchesVirtualPath, nil
}

func setContextDistro(packages []Package, ctx *Context) {
	if ctx.Distro != nil {
		return
	}
	var singleDistro *distro.Distro
	for _, p := range packages {
		if p.Distro == nil {
			continue
		}
		if singleDistro == nil {
			singleDistro = p.Distro
			continue
		}
		// if we have a distro already, ensure that the new one matches...
		if singleDistro.Type != p.Distro.Type ||
			singleDistro.Version != p.Distro.Version ||
			singleDistro.Codename != p.Distro.Codename {
			// ...if not then we bail, not setting a singular distro in the context
			return
		}
	}

	// if there is one distro (with one version) represented, use that
	if singleDistro != nil {
		ctx.Distro = singleDistro
	}
}
