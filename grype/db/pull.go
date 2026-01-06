package db

import (
	"context"
	"sync"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sync/semaphore"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type PullConfig struct {
	Parallelism int
	Collection  provider.Collection
}

func Pull(cfg PullConfig) error {
	var names []string
	for _, p := range cfg.Collection.Providers {
		names = append(names, p.ID().Name)
	}
	log.WithFields("providers", names).Info("aggregating vulnerability data")

	// TODO: validate config

	// execute config
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(int64(cfg.Parallelism))

	ctx := context.Background()

	var errs error
	var errsLock sync.Mutex
	updateErrs := func(err error) {
		if err != nil {
			errsLock.Lock()
			defer errsLock.Unlock()
			errs = multierror.Append(errs, err)
		}
	}

	for _, p := range cfg.Collection.Providers {
		if err := sem.Acquire(ctx, 1); err != nil {
			updateErrs(err)
			break
		}
		if errs != nil {
			// note: we don't cancel the context to stop existing provider updates. Why? this may leave otherwise
			// valid providers in a bad state. Instead, we just let the other providers that have already been started
			// to finish and return the error from the failed provider.
			log.WithFields("error", errs).Error("provider update failed, waiting for already started provider updates to finish before exiting...")
			break
		}
		wg.Add(1)
		go func(prov provider.Provider) {
			defer sem.Release(1)
			defer wg.Done()
			log.WithFields("provider", prov.ID().Name).Info("running vulnerability provider")
			updateErrs(prov.Update(ctx))
		}(p)
	}

	log.Trace("all providers started, waiting for graceful completion...")
	wg.Wait()

	return errs
}
