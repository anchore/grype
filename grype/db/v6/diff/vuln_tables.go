package diff

import (
	"strings"
)

// createDiffTablesVulns builds indexed temp tables from the given schema (main or new_db)
// with the given prefix (old or new) for table names.
func (d *DBDiffer) createDiffTablesVulns(suffix, schema string) error {
	r := strings.NewReplacer("{suffix}", suffix, "{db}", schema+".")

	templates := []string{
		// vulnerability lookup: resolved name + provider + status + dates + blob content
		`CREATE TEMP TABLE diff_vuln_{suffix} AS
		SELECT
			vh.provider_id,
			vh.name,
			COALESCE(vh.status, '') as status,
			COALESCE(vh.published_date, '') as published_date,
			COALESCE(vh.modified_date, '') as modified_date,
			COALESCE(vh.withdrawn_date, '') as withdrawn_date,
			COALESCE(b.value, '') AS vuln_blob
		FROM {db}vulnerability_handles vh
		JOIN {db}blobs b ON vh.blob_id = b.id
		`,
		`CREATE INDEX idx_diff_vuln_{suffix}_name_provider ON diff_vuln_{suffix} (name, provider_id)`,

		//// KEV entries
		`CREATE TEMP TABLE diff_kev_{suffix} AS
		SELECT cve FROM {db}known_exploited_vulnerability_handles`,
		`CREATE INDEX idx_diff_kev_{suffix}_cve ON diff_kev_{suffix}(cve)`,
	}

	return d.executeTemplates(templates, r)
}

func (d *DBDiffer) createDiffViewsVulns() error {
	r := strings.NewReplacer()

	templates := []string{
		`CREATE TEMP VIEW diff_vuln_added AS
		SELECT n.provider_id, n.name FROM diff_vuln_new n
		LEFT JOIN diff_vuln_old o
			ON o.provider_id = n.provider_id
			AND o.name = n.name
		WHERE o.name IS NULL`,

		`CREATE TEMP VIEW diff_vuln_modified AS
		SELECT n.provider_id, n.name FROM diff_vuln_new n
		JOIN diff_vuln_old o
			ON o.provider_id = n.provider_id
			AND o.name = n.name
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_vuln_old o
			WHERE o.provider_id = n.provider_id
			AND o.name = n.name
			AND o.status = n.status
			AND o.vuln_blob = n.vuln_blob
			AND o.modified_date = n.modified_date
			AND o.withdrawn_date = n.withdrawn_date
			AND o.published_date = n.published_date
		)`,

		`CREATE TEMP VIEW diff_vuln_removed AS
		SELECT o.provider_id, o.name FROM diff_vuln_old o
		LEFT JOIN diff_vuln_new n
			ON n.provider_id = o.provider_id
			AND n.name = o.name
		WHERE n.name IS NULL`,
	}

	return d.executeTemplates(templates, r)
}

func (d *DBDiffer) createDiffTablesEPSS(suffix, schema string) error {
	r := strings.NewReplacer("{suffix}", suffix, "{db}", schema+".")

	templates := []string{
		// EPSS scores
		`CREATE TEMP TABLE diff_epss_{suffix} AS
		SELECT cve, epss, percentile FROM {db}epss_handles`,
		`CREATE INDEX idx_diff_epss_{suffix}_cve ON diff_epss_{suffix}(cve)`,
	}

	return d.executeTemplates(templates, r)
}
