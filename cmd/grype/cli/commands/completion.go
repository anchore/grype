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

func dockerImageValidArgsFunction(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Since we use ValidArgsFunction, Cobra will call this AFTER having parsed all flags and arguments provided
	dockerImageRepoTags, err := listLocalDockerImages(toComplete)
	if err != nil {
		// Indicates that an error occurred and completions should be ignored
		return []string{"completion failed"}, cobra.ShellCompDirectiveError
	}
	if len(dockerImageRepoTags) == 0 {
		return []string{"no docker images found"}, cobra.ShellCompDirectiveError
	}
	// ShellCompDirectiveDefault indicates that the shell will perform its default behavior after completions have
	// been provided (without implying other possible directives)
	return dockerImageRepoTags, cobra.ShellCompDirectiveDefault
}
