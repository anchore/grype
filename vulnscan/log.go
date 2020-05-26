package vulnscan

import (
	"github.com/anchore/vulnscan/internal/log"
	"github.com/anchore/vulnscan/vulnscan/logger"
)

func SetLogger(logger logger.Logger) {
	log.Log = logger
}
