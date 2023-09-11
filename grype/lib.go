package grype

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

func SetLogger(l logger.Logger) {
	log.Set(l)
}

func SetBus(b *partybus.Bus) {
	bus.Set(b)
}
