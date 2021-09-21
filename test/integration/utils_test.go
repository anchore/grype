package integration

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter/packages"
	"github.com/anchore/syft/syft/source"
)

func getSyftSBOM(t testing.TB, image string) string {
	src, cleanup, err := source.New(image, nil)
	if err != nil {
		t.Fatalf("can't get the source: %+v", err)
	}
	t.Cleanup(cleanup)

	scope := source.SquashedScope
	catalog, distro, err := syft.CatalogPackages(src, scope)

	presenter := packages.Presenter(packages.JSONPresenterOption, packages.PresenterConfig{
		SourceMetadata: src.Metadata,
		Catalog:        catalog,
		Distro:         distro,
		Scope:          scope,
	})

	var buf bytes.Buffer
	if err := presenter.Present(bufio.NewWriter(&buf)); err != nil {
		t.Fatalf("presenter failed: %+v", err)
	}

	return buf.String()
}
