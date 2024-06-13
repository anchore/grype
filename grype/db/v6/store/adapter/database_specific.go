package adapter

import (
	"context"
	"database/sql"
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/store/repository"
)

const nvdDatabaseSpecificEntity = "nvd"

func stringRef(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

func (a *Adapter) AddDatabaseSpecificNVD(ctx context.Context, v v6.DatabaseSpecificNvd) error {
	fn := func(qtx *repository.Queries, id int64) error {
		_, err := qtx.CreateDatabaseSpecificNvd(ctx, repository.CreateDatabaseSpecificNvdParams{
			DbSpecificID:          id,
			Vulnstatus:            stringRef(v.VulnStatus),
			Cisaexploitadd:        stringRef(v.CisaExploitAdd),
			Cisaactiondue:         stringRef(v.CisaActionDue),
			Cisarequiredaction:    stringRef(v.CisaRequiredAction),
			Cisavulnerabilityname: stringRef(v.CisaVulnerabilityName),
		})
		return err
	}
	return a.addDatabaseSpecific(ctx, fn, nvdDatabaseSpecificEntity)
}

func (a *Adapter) addDatabaseSpecific(ctx context.Context, fn func(qtx *repository.Queries, id int64) error, entity string) error {
	if fn == nil || entity == "" {
		return fmt.Errorf("invalid database specific input input")
	}

	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qtx := a.API.WithTx(tx)
	id, err := qtx.CreateDatabaseSpecific(ctx, entity)
	if err != nil {
		return err
	}
	if err := fn(qtx, id); err != nil {
		return err
	}
	return tx.Commit()
}
