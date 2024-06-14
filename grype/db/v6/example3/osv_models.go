package main

type Vulnerability struct {
	ID            int64          `gorm:"primaryKey"`
	Name          string         `gorm:"column:name;not null"`
	SchemaVersion string         `gorm:"column:schema_version;not null"`
	Modified      string         `gorm:"column:modified"`
	Published     string         `gorm:"column:published"`
	Withdrawn     string         `gorm:"column:withdrawn"`
	Aliases       *[]Alias       `gorm:"many2many:vulnerability_aliases;"`
	Related       *[]Related     `gorm:"many2many:vulnerability_related;"`
	Summary       string         `gorm:"column:summary"`
	Details       string         `gorm:"column:details"`
	Severity      *[]Severity    `gorm:"foreignKey:VulnerabilityID"`
	Affected      *[]Affected    `gorm:"foreignKey:VulnerabilityID"`
	References    *[]Reference   `gorm:"many2many:vulnerability_references;"`
	Credits       *[]Credit      `gorm:"foreignKey:VulnerabilityID"`
	DbSpecificNvd *DbSpecificNvd `gorm:"foreignKey:VulnerabilityID"`
}

type DbSpecificNvd struct {
	ID                    int64  `gorm:"primaryKey"`
	VulnerabilityID       int64  `gorm:"column:vulnerability_id;not null"`
	VulnStatus            string `gorm:"column:vuln_status"`
	CisaExploitAdd        string `gorm:"column:cisa_exploit_add"`
	CisaActionDue         string `gorm:"column:cisa_action_due"`
	CisaRequiredAction    string `gorm:"column:cisa_required_action"`
	CisaVulnerabilityName string `gorm:"column:cisa_vulnerability_name"`
}

type Alias struct {
	ID    int64  `gorm:"primaryKey"`
	Alias string `gorm:"column:alias;not null;unique"`
}

type Related struct {
	ID      int64  `gorm:"primaryKey"`
	Related string `gorm:"column:related;not null;unique"`
}

type Severity struct {
	ID              int64  `gorm:"primaryKey"`
	VulnerabilityID int64  `gorm:"column:vulnerability_id;not null"`
	Type            string `gorm:"column:type;not null"`
	Score           string `gorm:"column:score;not null"`
}

type Affected struct {
	ID              int64               `gorm:"primaryKey"`
	VulnerabilityID int64               `gorm:"column:vulnerability_id;not null"`
	PackageID       int64               `gorm:"column:package_id;not null"`
	Package         *Package            `gorm:"foreignKey:PackageID"`
	Severity        *[]AffectedSeverity `gorm:"foreignKey:AffectedID"`
	Ranges          *[]Range            `gorm:"foreignKey:AffectedID"`
	Versions        *[]Version          `gorm:"foreignKey:AffectedID"`
}

type Package struct {
	ID        int64  `gorm:"primaryKey"`
	Ecosystem string `gorm:"column:ecosystem"`
	Name      string `gorm:"column:name"`
	Purl      string `gorm:"column:purl"`
}

type AffectedSeverity struct {
	ID         int64  `gorm:"primaryKey"`
	AffectedID int64  `gorm:"column:affected_id;not null"`
	Type       string `gorm:"column:type;not null"`
	Score      string `gorm:"column:score;not null"`
}

type Range struct {
	ID         int64         `gorm:"primaryKey"`
	AffectedID int64         `gorm:"column:affected_id;not null"`
	Type       string        `gorm:"column:type;not null"`
	Repo       string        `gorm:"column:repo"`
	Events     *[]RangeEvent `gorm:"foreignKey:RangeID"`
}

type RangeEvent struct {
	ID           int64  `gorm:"primaryKey"`
	RangeID      int64  `gorm:"column:range_id;not null"`
	Introduced   string `gorm:"column:introduced"`
	Fixed        string `gorm:"column:fixed"`
	LastAffected string `gorm:"column:last_affected"`
	Limit        string `gorm:"column:limit"`
}

type Version struct {
	ID         int64  `gorm:"primaryKey"`
	AffectedID int64  `gorm:"column:affected_id;not null"`
	Version    string `gorm:"column:version"`
}

type Reference struct {
	ID   int64  `gorm:"primaryKey"`
	Type string `gorm:"column:type;not null"`
	URL  string `gorm:"column:url;not null"`
}

type Credit struct {
	ID              int64      `gorm:"primaryKey"`
	VulnerabilityID int64      `gorm:"column:vulnerability_id;not null"`
	Name            string     `gorm:"column:name;not null"`
	Contact         *[]Contact `gorm:"foreignKey:CreditID"`
	Type            string     `gorm:"column:type;not null"`
}

type Contact struct {
	ID       int64  `gorm:"primaryKey"`
	CreditID int64  `gorm:"column:credit_id;not null"`
	Contact  string `gorm:"column:contact;not null"`
}
