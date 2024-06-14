package main

import (
	"fmt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// <-:create;    means that gorm is only allowed to read or create the field (no updates allowed)

type Vulnerability struct {
	ID int64 `gorm:"<-:create;column:id;primaryKey"`

	Name       string      `gorm:"<-:create;column:name;not null"`
	Aliases    *[]Alias    `gorm:"many2many:vulnerability_aliases;"`
	Severities *[]Severity `gorm:"many2many:vulnerability_severities"`
	Affecteds  *[]Affected `gorm:"foreignKey:VulnerabilityID"`
}

type Alias struct {
	ID int64 `gorm:"<-:create;column:id;primaryKey"`

	Alias string `gorm:"<-:create;column:alias;not null;index:idx_alias,unique"`
}

type Severity struct {
	ID int64 `gorm:"<-:create;column:id;primaryKey"`

	Type     string `gorm:"<-:create;column:type;not null;index:idx_severity,unique"`
	Score    string `gorm:"<-:create;column:score;not null;index:idx_severity,unique"`
	Source   string `gorm:"<-:create;column:source;index:idx_severity,unique"`
	Priority string `gorm:"<-:create;column:priority;index:idx_severity,unique"`
}

type Affected struct {
	ID              int64 `gorm:"<-:create;column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"<-:create;column:vulnerability_id,not null"`
	//Vulnerability   *Vulnerability

	AffectedPackageID *int64 `gorm:"<-:create;column:affected_package_id"`
	AffectedPackage   *AffectedPackage
}

type AffectedPackage struct {
	// TODO: setup unique indexes only for writing and drop before shipping for the best size tradeoff

	ID int64 `gorm:"<-:create;column:id;primaryKey"`

	// TODO: break purl out into fields here
	Ecosystem   string `gorm:"<-:create;column:ecosystem"`
	PackageName string `gorm:"<-:create;column:package_name;index:package_name"`
	Purl        string `gorm:"<-:create;column:purl"`
}

func main() {
	db, err := gorm.Open(sqlite.Open("/tmp/test.db"), &gorm.Config{})
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		return
	}
	db = db.Debug()

	// Automatically create the table based on the models
	if err := db.AutoMigrate(
		&Vulnerability{},
		&Alias{},
		&Severity{},
		&Affected{},
		&AffectedPackage{},
	); err != nil {
		fmt.Println("Failed to migrate database:", err)
		return
	}

	// Create some example data
	vulns := []*Vulnerability{
		{
			Name: "GHSA-xxxx-xxxx-xxxx1",
			Aliases: &[]Alias{
				{Alias: "CVE-2024-12341"},
			},
			Severities: &[]Severity{
				{
					Type:     "string",
					Score:    "high",
					Source:   "nvd",
					Priority: "primary",
				},
				{
					Type:     "string",
					Score:    "high",
					Source:   "nvd",
					Priority: "primary",
				},
				{
					Type:     "string",
					Score:    "medium",
					Source:   "cve",
					Priority: "secondary",
				},
			},
		},
		{
			Name:    "GHSA-xxxx-xxxx-xxxx2",
			Aliases: &[]Alias{
				//{Alias: "CVE-2024-12341"},
			},
			Severities: &[]Severity{
				{
					Type:     "string",
					Score:    "high",
					Source:   "nvd",
					Priority: "primary",
				},
				{
					Type:     "string",
					Score:    "medium",
					Source:   "cve",
					Priority: "secondary",
				},
				{
					Type:     "string",
					Score:    "medium",
					Source:   "somewhere-else",
					Priority: "secondary",
				},
			},
			Affecteds: &[]Affected{
				{
					AffectedPackage: &AffectedPackage{
						Ecosystem:   "golang",
						PackageName: "example-golang-package1",
						Purl:        "pkg:golang/example-golang-package1@1.0.0",
					},
				},
			},
		},
		{
			Name: "GHSA-xxxx-xxxx-xxxx3",
			Aliases: &[]Alias{
				{Alias: "CVE-2024-12341"},
			},
			Severities: &[]Severity{
				{
					Type:     "string",
					Score:    "low",
					Source:   "somewhere-else",
					Priority: "secondary",
				},
				{
					Type:     "string",
					Score:    "medium",
					Source:   "cve",
					Priority: "secondary",
				},
			},
		},
	}

	//for _, vuln := range vulns {
	//	fmt.Println("Creating associations for:", vuln.Name)
	//
	//	//db.Omit(clause.Associations).Create(&vuln).Error
	//	if vuln.Aliases != nil {
	//		aliases := *vuln.Aliases
	//		for i, alias := range aliases {
	//			if err := db.Where(&alias).FirstOrCreate(&aliases[i]).Error; err != nil {
	//				fmt.Println("Failed to create alias:", err)
	//				return
	//			}
	//		}
	//		vuln.Aliases = &aliases
	//	}
	//
	//	if vuln.Severities != nil {
	//		sevs := *vuln.Severities
	//		for i, sev := range sevs {
	//			fmt.Printf("Severity:      %#v\n", sev)
	//
	//			if err := db.Where(&sev).FirstOrCreate(&sevs[i]).Error; err != nil {
	//				fmt.Println("Failed to create severity:", err)
	//				return
	//			}
	//		}
	//		vuln.Severities = &sevs
	//	}
	//
	//	if vuln.Affecteds != nil {
	//		afs := *vuln.Affecteds
	//		for i, af := range afs {
	//			fmt.Printf("Affectives:      %#v\n", af)
	//
	//			if af.Package != nil {
	//				if err := db.Where(&af.Package).FirstOrCreate(af.Package).Error; err != nil {
	//					fmt.Println("Failed to create affected package:", err)
	//					return
	//				}
	//			}
	//
	//			if err := db.Where(&af).FirstOrCreate(&afs[i]).Error; err != nil {
	//				fmt.Println("Failed to create affected:", err)
	//				return
	//			}
	//		}
	//		vuln.Affecteds = &afs
	//	}
	//
	//	fmt.Println("Creating vulnerability:", vuln.Name)
	//
	//	if err := db.Create(&vuln).Error; err != nil {
	//		fmt.Println("Failed to create vulnerability:", err)
	//		return
	//	}
	//}

	if err := InsertVulnerabilities(db, vulns); err != nil {
		fmt.Println("Failed to create vulnerability:", err)
		return
	}

	fmt.Println("Database migrated and example data created successfully.")
}

func InsertVulnerabilities(db *gorm.DB, vulns []*Vulnerability) error {
	for _, vuln := range vulns {
		// Create Vulnerability
		if err := db.Create(vuln).Error; err != nil {
			return fmt.Errorf("failed to create vulnerability: %w", err)
		}

		// Create or find Aliases and associate with Vulnerability
		if vuln.Aliases != nil {
			for _, alias := range *vuln.Aliases {
				var existingAlias Alias
				if err := db.Where("alias = ?", alias.Alias).FirstOrCreate(&existingAlias).Error; err != nil {
					return fmt.Errorf("failed to create or find alias: %w", err)
				}
				if err := db.Model(vuln).Association("Aliases").Append(&existingAlias); err != nil {
					return fmt.Errorf("failed to associate alias: %w", err)
				}
			}
		}

		// Create or find Severities and associate with Vulnerability
		if vuln.Severities != nil {
			for _, severity := range *vuln.Severities {
				var existingSeverity Severity
				if err := db.Where("type = ? AND score = ? AND source = ? AND priority = ?", severity.Type, severity.Score, severity.Source, severity.Priority).FirstOrCreate(&existingSeverity).Error; err != nil {
					return fmt.Errorf("failed to create or find severity: %w", err)
				}
				if err := db.Model(vuln).Association("Severities").Append(&existingSeverity); err != nil {
					return fmt.Errorf("failed to associate severity: %w", err)
				}
			}
		}

		// Create Affecteds and AffectedPackages
		if vuln.Affecteds != nil {
			for _, affected := range *vuln.Affecteds {
				if affected.AffectedPackage != nil {
					var existingPackage AffectedPackage
					if err := db.Where("ecosystem = ? AND package_name = ? AND purl = ?", affected.AffectedPackage.Ecosystem, affected.AffectedPackage.PackageName, affected.AffectedPackage.Purl).FirstOrCreate(&existingPackage).Error; err != nil {
						return fmt.Errorf("failed to create or find affected package: %w", err)
					}
					affected.AffectedPackageID = &existingPackage.ID
				}
				if err := db.Create(&affected).Error; err != nil {
					return fmt.Errorf("failed to create affected: %w", err)
				}
				if err := db.Model(vuln).Association("Affecteds").Append(&affected); err != nil {
					return fmt.Errorf("failed to associate affected: %w", err)
				}
			}
		}
	}
	return nil
}

// one to many

//type Vulnerability struct {
//	ID int64 `gorm:"column:id;primaryKey"`
//
//	Name       string      `gorm:"<-:create;column:name;not null"`
//	Aliases    *[]Alias    //`gorm:"many2many:vulnerability_aliases;"`
//	Severities *[]Severity //`gorm:"many2many:vulnerability_severities"`
//}
//
//type Alias struct {
//	ID              int64 `gorm:"<-:create;column:id;primaryKey"`
//	VulnerabilityID int64 `gorm:"<-:create;column:vulnerability_id;index"`
//
//	Alias string `gorm:"<-:create;column:alias;not null;unique"`
//}
//
//type Severity struct {
//	ID              int64 `gorm:"<-:create;column:id;primaryKey"`
//	VulnerabilityID int64 `gorm:"<-:create;column:vulnerability_id;index"`
//
//	Type     string `gorm:"<-:create;column:type;not null;index:idx_severity,unique"`
//	Score    string `gorm:"<-:create;column:score;not null;index:idx_severity,unique"`
//	Source   string `gorm:"<-:create;column:source;index:idx_severity,unique"`
//	Priority string `gorm:"<-:create;column:priority;index:idx_severity,unique"`
//}
//
//func main() {
//	db, err := gorm.Open(sqlite.Open("/tmp/test.db"), &gorm.Config{})
//	if err != nil {
//		fmt.Println("Failed to connect to database:", err)
//		return
//	}
//
//	// Automatically create the table based on the models
//	if err := db.AutoMigrate(
//		&Vulnerability{},
//		&Alias{},
//		&Severity{},
//	); err != nil {
//		fmt.Println("Failed to migrate database:", err)
//		return
//	}
//
//	// Create some example data
//	vulns := []*Vulnerability{
//		{
//			Name: "GHSA-xxxx-xxxx-xxxx1",
//			Aliases: &[]Alias{
//				{Alias: "CVE-2024-12341"},
//			},
//			Severities: &[]Severity{
//				{
//					Type:     "string",
//					Score:    "high",
//					Source:   "nvd",
//					Priority: "primary",
//				},
//				{
//					Type:     "string",
//					Score:    "high",
//					Source:   "nvd",
//					Priority: "primary",
//				},
//				{
//					Type:     "string",
//					Score:    "medium",
//					Source:   "cve",
//					Priority: "secondary",
//				},
//			},
//		},
//		{
//			Name: "GHSA-xxxx-xxxx-xxxx2",
//			Aliases: &[]Alias{
//				{Alias: "CVE-2024-12341"},
//			},
//			Severities: &[]Severity{
//				{
//					Type:     "string",
//					Score:    "high",
//					Source:   "nvd",
//					Priority: "primary",
//				},
//				{
//					Type:     "string",
//					Score:    "medium",
//					Source:   "cve",
//					Priority: "secondary",
//				},
//				{
//					Type:     "string",
//					Score:    "medium",
//					Source:   "somewhere-else",
//					Priority: "secondary",
//				},
//			},
//		},
//	}
//
//	for _, vuln := range vulns {
//		fmt.Println("Creating associations for:", vuln.Name, vuln.Aliases)
//
//		// db.Omit(clause.Associations).Create(&vuln).Error
//		for _, alias := range *vuln.Aliases {
//			if err := db.FirstOrCreate(&alias).Error; err != nil {
//				fmt.Println("Failed to create alias:", err)
//				return
//			}
//		}
//
//		for _, sev := range *vuln.Severities {
//			//if err := db.Where("type = ? AND score = ? AND source = ? AND priority = ?", sev.Type, sev.Score, sev.Source, sev.Priority).FirstOrCreate(&sev).Error; err != nil {
//			//	fmt.Println("Failed to create severity:", err)
//			//	return
//			//}
//			if err := db.Omit("ID").Where(&sev).FirstOrCreate(&sev).Error; err != nil {
//				fmt.Println("Failed to create severity:", err)
//				return
//			}
//		}
//
//		fmt.Println("Creating vulnerability:", vuln.Name)
//
//		if err := db.Omit(clause.Associations).Create(&vuln).Error; err != nil {
//			fmt.Println("Failed to create vulnerability:", err)
//			return
//		}
//	}
//
//	fmt.Println("Database migrated and example data created successfully.")
//}
