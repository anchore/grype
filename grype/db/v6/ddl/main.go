package main

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/store/adapter"
	"github.com/anchore/grype/grype/db/v6/store/repository"
	"log"
	_ "modernc.org/sqlite"
)

//go:embed schema/6_0_0.sql
var ddl string

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}

	// create tables
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return err
	}

	a := adapter.New(db)

	err = a.AddDatabaseSpecificNVD(ctx, v6.DatabaseSpecificNvd{
		VulnStatus:            "",
		CisaExploitAdd:        "",
		CisaActionDue:         "",
		CisaRequiredAction:    "",
		CisaVulnerabilityName: "",
	})

	if err != nil {
		return err
	}

	dbSpecNvd, err := a.API.ListDatabaseSpecificNvd(ctx)
	if err != nil {
		return err
	}

	fmt.Println("All Database Specific NVD:")
	for _, s := range dbSpecNvd {
		log.Printf("%#v\n", s)
	}

	dbSpec, err := a.API.ListDatabaseSpecific(ctx)
	if err != nil {
		return err
	}

	fmt.Println("All Database Specific:")
	for _, s := range dbSpec {
		log.Printf("%#v\n", s)
	}

	return nil
}

//func stringPtr(s string) *string {
//	return &s
//}

func stringPtr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

//func run() error {
//	ctx := context.Background()
//
//	db, err := sql.Open("sqlite", ":memory:")
//	if err != nil {
//		return err
//	}
//
//	// create tables
//	if _, err := db.ExecContext(ctx, ddl); err != nil {
//		return err
//	}
//
//	queries := repository.New(db)
//
//	// create OS
//	_, err = queries.CreateOperatingSystem(ctx, repository.CreateOperatingSystemParams{
//		Name:         "redhat",
//		MajorVersion: "7",
//		MinorVersion: stringPtr("2"),
//		Codename:     stringPtr("something-else"),
//	})
//	if err != nil {
//		return err
//	}
//	//log.Printf("%#v\n", os)
//
//	_, err = queries.CreateOperatingSystem(ctx, repository.CreateOperatingSystemParams{
//		Name:         "redhat",
//		MajorVersion: "8",
//		MinorVersion: stringPtr("2"),
//		Codename:     stringPtr("maipo"),
//	})
//	if err != nil {
//		return err
//	}
//
//	allOS, err := queries.ListOperatingSystems(ctx) //&repository.ListOperatingSystemsParams{
//	//	Name:         "redhat",
//	//	MajorVersion: "8",
//	//	//MinorVersion: stringPtr("2"),
//	//	//Codename: stringPtr("maipo"),
//	//},
//
//	if err != nil {
//		return err
//	}
//
//	fmt.Println("All OS:")
//	for _, os := range allOS {
//		log.Printf("%s\n", osStringer{os})
//	}
//
//	//_, err = queries.CreateAffectedDistroPackage(ctx, repository.CreateAffectedDistroPackageParams{
//	//	PackageName: "name!",
//	//	OsID:        rhel8.OsID,
//	//})
//	//if err != nil {
//	//	return err
//	//}
//	//
//	////log.Printf("%#v\n", os)
//	//
//	//allOS, err := queries.ListOperatingSystems(ctx)
//	//if err != nil {
//	//	return err
//	//}
//	//
//	//fmt.Println("All OS:")
//	//for _, os := range allOS {
//	//	log.Printf("%#v\n", os)
//	//}
//	//
//	//allAffected, err := queries.ListAffectedDistroPackagesByPackageNameAndOsMajorMinorVersion(ctx,
//	//	repository.ListAffectedDistroPackagesByPackageNameAndOsMajorMinorVersionParams{
//	//		PackageName:  "name!",
//	//		Name:         "redhat",
//	//		MajorVersion: "8",
//	//	})
//	//if err != nil {
//	//	return err
//	//}
//	//
//	//fmt.Println("All Affected:")
//	//for _, affected := range allAffected {
//	//	log.Printf("%#v\n", affected)
//	//}
//
//	return nil
//}

type osStringer struct {
	repository.OperatingSystem
}

func (o osStringer) String() string {

	//mi := "?"
	//if o.MinorVersion != nil {
	//	mi = "." + *o.MinorVersion
	//}
	//
	//var co string
	//if o.Codename != nil {
	//	co = fmt.Sprintf(", codename=%s", *o.Codename)
	//}
	//return fmt.Sprintf("OS(%s@%s%s%s)", o.Name, o.MajorVersion, mi, co)
	return fmt.Sprintf("OS(%s@%s.%s %s)", o.Name, o.MajorVersion, o.MinorVersion.String, o.Codename.String)
}
