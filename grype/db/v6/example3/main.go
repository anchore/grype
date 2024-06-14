package main

import (
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func main() {
	// Initialize GORM with a SQLite database
	db, err := gorm.Open(sqlite.Open("/tmp/example3.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	db = db.Debug()

	// Migrate the schema
	err = db.AutoMigrate(
		&Vulnerability{}, &Alias{}, &Related{}, &Severity{}, &Affected{}, &Package{}, &AffectedSeverity{}, &Range{}, &RangeEvent{}, &Version{}, &Reference{}, &Credit{}, &Contact{},
		//&JSONB{},
	)
	if err != nil {
		panic("failed to migrate schema")
	}

	// Populate test fixture
	vulns := populateTestFixture()
	for _, vuln := range vulns {
		fmt.Println("Creating vulnerability record", vuln.ID)
		if err := db.Create(&vuln).Error; err != nil {
			fmt.Println("failed to create vulnerability record: %w", err)
		}
	}
	fmt.Println("Test fixture populated")
}
