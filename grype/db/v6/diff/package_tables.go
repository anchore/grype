package diff

import (
	"strings"
)

// createDiffTablesPackages builds indexed temp tables from the given schema (main or new_db)
// with the given suffix (old or new) for table names.
//
//nolint:funlen
func (d *DBDiffer) createDiffTablesPackages(db, schema string) error {
	r := strings.NewReplacer("{suffix}", db, "{db}", schema+".")

	templates := []string{
		// package + language/os + vulnerability
		`CREATE TEMP TABLE diff_pkg_{suffix} AS
		 SELECT p.ecosystem,
			p.name AS pkg_name,
			-- get blob with information removed that does not affect matching
			json_set(pb.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(pb.value, '$.ranges')))
				AS pkg_blob,
			vh.provider_id,
			CASE WHEN LOWER(vh.status) IN ('withdrawn', 'rejected') THEN 0 ELSE 1 END AS status, -- 0: not vulnerable
			vh.name AS vuln_name,
			vh.id AS vulnerability_id,
			COALESCE(os.name, '') AS os_name,
			COALESCE(os.major_version, '') AS os_major,
			COALESCE(os.minor_version, '') AS os_minor,
			COALESCE(os.codename, '') AS os_codename,
			COALESCE(os.channel, '') AS os_channel
		 FROM {db}affected_package_handles aph
		 JOIN {db}vulnerability_handles vh ON aph.vulnerability_id = vh.id
		 JOIN {db}packages p ON aph.package_id = p.id
		 JOIN {db}blobs pb ON aph.blob_id = pb.id
		 LEFT JOIN {db}operating_systems os ON aph.operating_system_id = os.id
		 UNION
		 SELECT p.ecosystem,
			p.name AS pkg_name,
			-- get blob with information removed that does not affect matching
			json_set(pb.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(pb.value, '$.ranges')))
				AS pkg_blob,
			vh.provider_id,
			0 AS status, -- unaffected records are always a not-vulnerable status
			vh.name AS vuln_name,
			vh.id AS vulnerability_id,
			COALESCE(os.name, '') AS os_name,
			COALESCE(os.major_version, '') AS os_major,
			COALESCE(os.minor_version, '') AS os_minor,
			COALESCE(os.codename, '') AS os_codename,
			COALESCE(os.channel, '') AS os_channel
		 FROM {db}unaffected_package_handles aph
		 JOIN {db}vulnerability_handles vh ON aph.vulnerability_id = vh.id
		 JOIN {db}packages p ON aph.package_id = p.id
		 JOIN {db}blobs pb ON aph.blob_id = pb.id
		 LEFT JOIN {db}operating_systems os ON aph.operating_system_id = os.id
		 `,
		`CREATE INDEX idx_pkg_{suffix} ON diff_pkg_{suffix} (vuln_name, provider_id, ecosystem, pkg_name, os_name, os_major, os_minor, os_channel)`,

		// CPE relationships: resolved vuln + CPE + blob
		`CREATE TEMP TABLE diff_cpe_{suffix} AS
		 SELECT vh.name AS vuln_name,
			vh.provider_id,
			vh.id AS vulnerability_id,
			CASE WHEN LOWER(vh.status) IN ('withdrawn', 'rejected') THEN 0 ELSE 1 END AS status, -- 0: not vulnerable
			c.part,
			c.vendor,
			c.product,
			c.edition,
			c.language,
			c.software_edition AS sw_edition,
			c.target_hardware AS target_hw,
			c.target_software AS target_sw,
			c.other,
			-- get CPE blob with information removed that does not affect matching
		    json_set(cb.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(cb.value, '$.ranges')))
				AS cpe_blob
		 FROM {db}affected_cpe_handles ach
		 JOIN {db}vulnerability_handles vh ON ach.vulnerability_id = vh.id
		 JOIN {db}cpes c ON ach.cpe_id = c.id
		 JOIN {db}blobs cb ON ach.blob_id = cb.id
		 UNION
		 SELECT vh.name AS vuln_name,
			vh.provider_id,
			vh.id AS vulnerability_id,
			0 AS status, -- unaffected records are always a not-vulnerable status
			c.part,
			c.vendor,
			c.product,
			c.edition,
			c.language,
			c.software_edition AS sw_edition,
			c.target_hardware AS target_hw,
			c.target_software AS target_sw,
			c.other,
			-- get CPE blob with information removed that does not affect matching
		    json_set(cb.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(cb.value, '$.ranges')))
				AS cpe_blob
		 FROM {db}unaffected_cpe_handles ach
		 JOIN {db}vulnerability_handles vh ON ach.vulnerability_id = vh.id
		 JOIN {db}cpes c ON ach.cpe_id = c.id
		 JOIN {db}blobs cb ON ach.blob_id = cb.id
		 `,
		`CREATE INDEX idx_cpe_{suffix} ON diff_cpe_{suffix} (vuln_name, provider_id, part, vendor, product)`,
	}

	return d.executeTemplates(templates, r)
}

//nolint:funlen
func (d *DBDiffer) createDiffViewsPackages() error {
	r := strings.NewReplacer()

	templates := []string{
		`CREATE TEMP VIEW diff_pkg_added AS
		SELECT DISTINCT
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM diff_pkg_new p
		LEFT JOIN diff_pkg_old p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		WHERE p2.vuln_name IS NULL
		OR (p.status = 1 AND p2.status = 0)`,

		`CREATE TEMP VIEW diff_pkg_removed AS
		SELECT DISTINCT
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM diff_pkg_old p
		LEFT JOIN diff_pkg_new p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		WHERE p2.vuln_name IS NULL
		OR (p.status = 1 AND p2.status = 0)`,

		`CREATE TEMP VIEW diff_pkg_modified AS
		SELECT DISTINCT
			p.vulnerability_id,
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM diff_pkg_old p
		JOIN diff_pkg_new p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
			AND p.status = p2.status
		WHERE NOT EXISTS(
			SELECT 1 FROM diff_pkg_new p2
			WHERE p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
			AND p.pkg_blob = p2.pkg_blob
			AND p.status = p2.status
		)`,

		`CREATE TEMP VIEW diff_cpe_added AS
		SELECT DISTINCT
		    c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name
		FROM diff_cpe_new c
		LEFT JOIN diff_cpe_old c2
			ON c.vuln_name = c2.vuln_name
			AND c.provider_id = c2.provider_id
			AND c.part = c2.part
			AND c.vendor = c2.vendor
			AND c.product = c2.product
			AND c.edition = c2.edition
			AND c.language = c2.language
			AND c.sw_edition = c2.sw_edition
			AND c.target_hw = c2.target_hw
			AND c.target_sw = c2.target_sw
			AND c.other = c2.other
		WHERE c2.vuln_name IS NULL
		OR (c.status = 1 AND c2.status = 0)`,

		`CREATE TEMP VIEW diff_cpe_removed AS
		SELECT DISTINCT
		    c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name
		FROM diff_cpe_old c
		LEFT JOIN diff_cpe_new c2
			ON c.vuln_name = c2.vuln_name
			AND c.provider_id = c2.provider_id
			AND c.part = c2.part
			AND c.vendor = c2.vendor
			AND c.product = c2.product
			AND c.edition = c2.edition
			AND c.language = c2.language
			AND c.sw_edition = c2.sw_edition
			AND c.target_hw = c2.target_hw
			AND c.target_sw = c2.target_sw
			AND c.other = c2.other
		WHERE c2.vuln_name IS NULL 
		OR (c.status = 1 AND c2.status = 0)`,

		`CREATE TEMP VIEW diff_cpe_modified AS
		SELECT DISTINCT
			c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name, c.cpe_blob, c2.cpe_blob
		FROM diff_cpe_old c
		JOIN diff_cpe_new c2
			ON c.vuln_name = c2.vuln_name
			AND c.provider_id = c2.provider_id
			AND c.part = c2.part
			AND c.vendor = c2.vendor
			AND c.product = c2.product
			AND c.edition = c2.edition
			AND c.language = c2.language
			AND c.sw_edition = c2.sw_edition
			AND c.target_hw = c2.target_hw
			AND c.target_sw = c2.target_sw
			AND c.other = c2.other
			AND c.status = c2.status
		WHERE NOT EXISTS (
			SELECT 1 FROM diff_cpe_new c2
			WHERE c.vuln_name = c2.vuln_name
			AND c.provider_id = c2.provider_id
			AND c.part = c2.part
			AND c.vendor = c2.vendor
			AND c.product = c2.product
			AND c.edition = c2.edition
			AND c.language = c2.language
			AND c.sw_edition = c2.sw_edition
			AND c.target_hw = c2.target_hw
			AND c.target_sw = c2.target_sw
			AND c.other = c2.other
			AND c.status = c2.status
			AND c.cpe_blob = c2.cpe_blob
		)`,
	}

	return d.executeTemplates(templates, r)
}
