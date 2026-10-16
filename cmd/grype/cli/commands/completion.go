package commands

import (
	"context"
	"os"
	"strings"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

// Completion returns a command to provide completion to various terminal shells
func Completion(app clio.Application) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate a shell completion for Grype (listing local docker images)",
		Long: `To load completions (docker image list):

Bash:

$ source <(grype completion bash)

# To load completions for each session, execute once:
Linux:
  $ grype completion bash > /etc/bash_completion.d/grype
MacOS:
  $ grype completion bash > /usr/local/etc/bash_completion.d/grype

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ grype completion zsh > "${fpath[1]}/_grype"

# You will need to start a new shell for this setup to take effect.

Fish:

$ grype completion fish | source

# To load completions for each session, execute once:
$ grype completion fish > ~/.config/fish/completions/grype.fish
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "fish", "zsh"},
		PreRunE:               disableUI(app),
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			switch args[0] {
			case "zsh":
				err = cmd.Root().GenZshCompletion(os.Stdout)
			case "bash":
				err = cmd.Root().GenBashCompletion(os.Stdout)
			case "fish":
				err = cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			return err
		},
	}
}

// targetSchemePrefixes is the set of scheme prefixes documented in the root command's long help text.
// Each entry includes the trailing ":" so that completion produces a value the user can keep typing
// after without having to add the separator themselves.
var targetSchemePrefixes = []string{
	"docker:",
	"podman:",
	"docker-archive:",
	"oci-archive:",
	"oci-dir:",
	"singularity:",
	"registry:",
	"dir:",
	"file:",
	"sbom:",
	"purl:",
	"cpes:",
}

// imageSchemePrefixes is the subset of scheme prefixes for which we can usefully enumerate local
// Docker daemon images (the docker SDK speaks to both Docker and Podman daemons via DOCKER_HOST).
var imageSchemePrefixes = []string{
	"docker:",
	"podman:",
}

func listLocalDockerImages(prefix string) ([]string, error) {
	var repoTags = make([]string, 0)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return repoTags, err
	}

	// Only want to return tagged images
	imageListArgs := filters.NewArgs()
	imageListArgs.Add("dangling", "false")
	images, err := cli.ImageList(ctx, image.ListOptions{All: false, Filters: imageListArgs})
	if err != nil {
		return repoTags, err
	}

	for _, image := range images {
		// image may have multiple tags
		for _, tag := range image.RepoTags {
			if strings.HasPrefix(tag, prefix) {
				repoTags = append(repoTags, tag)
			}
		}
	}
	return repoTags, nil
}

// schemePrefixCompletions returns the subset of known scheme prefixes that begin with toComplete.
// When the user has typed nothing yet, all known prefixes are returned.
func schemePrefixCompletions(toComplete string) []string {
	matches := make([]string, 0, len(targetSchemePrefixes))
	for _, p := range targetSchemePrefixes {
		if strings.HasPrefix(p, toComplete) {
			matches = append(matches, p)
		}
	}
	return matches
}

// hasImageScheme reports whether toComplete starts with a scheme that we can enumerate via the
// local container daemon.
func hasImageScheme(toComplete string) (string, bool) {
	for _, p := range imageSchemePrefixes {
		if strings.HasPrefix(toComplete, p) {
			return p, true
		}
	}
	return "", false
}

// hasAnyTargetScheme reports whether toComplete starts with any known scheme prefix.
func hasAnyTargetScheme(toComplete string) bool {
	for _, p := range targetSchemePrefixes {
		if strings.HasPrefix(toComplete, p) {
			return true
		}
	}
	return false
}

func dockerImageValidArgsFunction(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Since we use ValidArgsFunction, Cobra will call this AFTER having parsed all flags and arguments provided.
	// The scan target argument can be an image name (the historical default), or any of the documented scheme
	// prefixes (registry:, dir:, file:, oci-archive:, ...). We suggest scheme prefixes when the partial input
	// either matches a prefix or is empty, and we enumerate local container images when the input is plain or
	// uses a daemon-backed scheme. For file- and dir-based schemes we fall through to the shell's default
	// completion so it can expand paths after the colon.
	if scheme, ok := hasImageScheme(toComplete); ok {
		// strip the scheme to query the daemon, then re-attach the scheme to each suggestion
		stripped := strings.TrimPrefix(toComplete, scheme)
		tags, err := listLocalDockerImages(stripped)
		if err != nil || len(tags) == 0 {
			return nil, cobra.ShellCompDirectiveDefault
		}
		out := make([]string, 0, len(tags))
		for _, t := range tags {
			out = append(out, scheme+t)
		}
		return out, cobra.ShellCompDirectiveDefault
	}

	if hasAnyTargetScheme(toComplete) {
		// a non-image scheme is in play (sbom:, dir:, file:, ...); let the shell complete the path
		return nil, cobra.ShellCompDirectiveDefault
	}

	// no scheme typed yet: offer scheme prefixes plus the historical docker-image suggestions. We use
	// ShellCompDirectiveNoSpace so that "dir:" can be followed by a path without the shell jumping to
	// a new token, and ShellCompDirectiveDefault so the shell still offers filename completion when
	// the user ignores our suggestions.
	completions := schemePrefixCompletions(toComplete)
	if tags, err := listLocalDockerImages(toComplete); err == nil {
		completions = append(completions, tags...)
	}
	if len(completions) == 0 {
		return nil, cobra.ShellCompDirectiveDefault
	}
	return completions, cobra.ShellCompDirectiveNoSpace | cobra.ShellCompDirectiveDefault
}
