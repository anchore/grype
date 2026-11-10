package v6

import (
	"fmt"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/schemaver"
)

type SearchRuleStoreReader interface {
	// GetSearchRules returns the search rules this client applies, in table order. A DB that predates the
	// table gets the built-in KnownSearchRules; otherwise the table is authoritative, even when it is empty
	// or every row is skipped. Rows this client cannot apply are skipped with a warning.
	GetSearchRules() []SearchRule
}

// searchRulesIntroduced is the first DB schema with the search_rules table. Hydrating an older DB
// creates the table empty, so a table alone does not mean the DB has rules to say.
var searchRulesIntroduced = schemaver.New(6, 1, 11)

type searchRuleStore struct {
	db        *gorm.DB
	dbVersion schemaver.SchemaVer
}

func newSearchRuleStore(db *gorm.DB, dbVersion schemaver.SchemaVer) *searchRuleStore {
	return &searchRuleStore{db: db, dbVersion: dbVersion}
}

// searchRuleRow is a search_rules row as read, with where it is and whether it sets a column this
// client does not know.
type searchRuleRow struct {
	SearchRule
	RowID       int64 `gorm:"column:search_rule_rowid"`
	SetsUnknown bool  `gorm:"column:sets_unknown_column"`
}

func (s *searchRuleStore) GetSearchRules() []SearchRule {
	if s.dbVersion.LessThan(searchRulesIntroduced) || !s.db.Migrator().HasTable(&SearchRule{}) {
		return applicableSearchRules(builtInSearchRules(), nil)
	}
	rows, unknown, err := s.readSearchRules()
	if err != nil {
		log.WithFields("error", err).Warn("unable to read search rules from DB; using the built-in rules")
		return applicableSearchRules(builtInSearchRules(), nil)
	}
	return applicableSearchRules(rows, unknown)
}

// readSearchRules reads every row in rowid order, flagging rows that set a column the SearchRule model
// does not map (unknown): gorm would drop such a column, and with it a predicate a newer DB narrowed the
// rule by.
func (s *searchRuleStore) readSearchRules() (rows []searchRuleRow, unknown []string, err error) {
	stmt := &gorm.Statement{DB: s.db}
	if err := stmt.Parse(&SearchRule{}); err != nil {
		return nil, nil, fmt.Errorf("unable to parse the search rule model: %w", err)
	}
	columns, err := s.db.Migrator().ColumnTypes(&SearchRule{})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read search rule columns: %w", err)
	}

	setsUnknown := "0"
	var conds []string
	for _, c := range columns {
		if _, ok := stmt.Schema.FieldsByDBName[c.Name()]; ok {
			continue
		}
		unknown = append(unknown, c.Name())
		q := stmt.Quote(c.Name())
		conds = append(conds, fmt.Sprintf("(%s IS NOT NULL AND %s != '')", q, q))
	}
	if len(conds) > 0 {
		setsUnknown = strings.Join(conds, " OR ")
	}

	query := fmt.Sprintf("SELECT rowid AS search_rule_rowid, *, (%s) AS sets_unknown_column FROM %s ORDER BY rowid",
		setsUnknown, stmt.Quote(stmt.Schema.Table))
	if err := s.db.Raw(query).Scan(&rows).Error; err != nil {
		return nil, nil, fmt.Errorf("unable to read search rules: %w", err)
	}
	return rows, unknown, nil
}

func builtInSearchRules() []searchRuleRow {
	known := KnownSearchRules()
	rows := make([]searchRuleRow, len(known))
	for i, r := range known {
		rows[i].SearchRule = r
	}
	return rows
}

// applicableSearchRules returns the rules of rows this client applies, in order: those its client schema
// constraint allows, that set none of the unknown columns, and that are valid. Skipped rows warn once
// per process.
func applicableSearchRules(rows []searchRuleRow, unknown []string) []SearchRule {
	client := version.New(fmt.Sprintf("%d.%d.%d", ModelVersion, Revision, Addition), version.SemanticFormat)
	out := make([]SearchRule, 0, len(rows))
	var skippedUnknown int
	for _, row := range rows {
		ok, err := clientSchemaAllows(row.ApplicableClientDBSchemas, client)
		switch {
		case err != nil:
			warnSkippedSearchRule(row, fmt.Errorf("invalid client schema constraint %q: %w", row.ApplicableClientDBSchemas, err))
			continue
		case !ok:
			continue
		case row.SetsUnknown:
			skippedUnknown++
			continue
		}
		if err := row.Validate(); err != nil {
			warnSkippedSearchRule(row, err)
			continue
		}
		out = append(out, row.SearchRule)
	}
	if skippedUnknown > 0 {
		warnOnce(fmt.Sprint("unknown search rule columns ", unknown), "skipping search rules that set columns this grype version does not know",
			"columns", strings.Join(unknown, ", "), "rules", skippedUnknown)
	}
	return out
}

func warnSkippedSearchRule(row searchRuleRow, err error) {
	warnOnce(fmt.Sprintf("search rule %d: %v", row.RowID, err), "skipping search rule this grype version cannot apply",
		"rowid", row.RowID, "action", row.Action, "distro", row.MatchDistroName, "ecosystem", row.MatchEcosystem, "error", err)
}

// warnedSearchRules are the keys warnOnce has warned for: the DB is loaded once per provider, which a
// process may make more than one of.
var warnedSearchRules sync.Map

func warnOnce(key, msg string, fields ...any) {
	if _, warned := warnedSearchRules.LoadOrStore(key, struct{}{}); warned {
		log.WithFields(fields...).Debug(msg)
		return
	}
	log.WithFields(fields...).Warn(msg)
}
