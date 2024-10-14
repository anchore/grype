package commands

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

func Test_applyDistroHint(t *testing.T) {
	ctx := pkg.Context{}
	cfg := options.Grype{}

	applyDistroHint([]pkg.Package{}, &ctx, &cfg)
	assert.Nil(t, ctx.Distro)

	// works when distro is nil
	cfg.Distro = "alpine:3.10"
	applyDistroHint([]pkg.Package{}, &ctx, &cfg)
	assert.NotNil(t, ctx.Distro)

	assert.Equal(t, "alpine", ctx.Distro.Name)
	assert.Equal(t, "3.10", ctx.Distro.Version)

	// does override an existing distro
	cfg.Distro = "ubuntu:latest"
	applyDistroHint([]pkg.Package{}, &ctx, &cfg)
	assert.NotNil(t, ctx.Distro)

	assert.Equal(t, "ubuntu", ctx.Distro.Name)
	assert.Equal(t, "latest", ctx.Distro.Version)

	// doesn't remove an existing distro when empty
	cfg.Distro = ""
	applyDistroHint([]pkg.Package{}, &ctx, &cfg)
	assert.NotNil(t, ctx.Distro)

	assert.Equal(t, "ubuntu", ctx.Distro.Name)
	assert.Equal(t, "latest", ctx.Distro.Version)
}

func Test_getProviderConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *options.Grype
		want pkg.ProviderConfig
	}{
		{
			name: "syft default api options are used",
			opts: options.DefaultGrype(clio.Identification{
				Name:    "test",
				Version: "1.0",
			}),
			want: pkg.ProviderConfig{
				SyftProviderConfig: pkg.SyftProviderConfig{
					SBOMOptions: func() *syft.CreateSBOMConfig {
						cfg := syft.DefaultCreateSBOMConfig()
						cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop
						return cfg
					}(),
					RegistryOptions: &image.RegistryOptions{
						Credentials: []image.RegistryCredentials{},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := cmp.Options{
				cmpopts.IgnoreFields(binary.Classifier{}, "EvidenceMatcher"),
				cmpopts.IgnoreUnexported(syft.CreateSBOMConfig{}),
			}
			if d := cmp.Diff(tt.want, getProviderConfig(tt.opts), opts...); d != "" {
				t.Errorf("getProviderConfig() mismatch (-want +got):\n%s", d)
			}
		})
	}
}
