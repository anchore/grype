package grype

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/log"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}

func SetBus(b *partybus.Bus) {
	bus.SetPublisher(b)
}
