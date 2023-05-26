package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/internal/config"
)

func Test_applyDistroHint(t *testing.T) {
	ctx := pkg.Context{}
	cfg := config.Application{}

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
