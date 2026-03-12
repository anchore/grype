package diff

import (
	"strings"
)

// createDiffTablesPackages builds indexed temp tables from the given schema (main or new_db)
// with the given prefix (old or new) for table names.
func (d *DBDiffer) createDiffTablesPackages(prefix, schema string) error {
	r := strings.NewReplacer("{prefix}", prefix, "{db}", schema+".")

	templates := []string{
		// package + language/os + vulnerability
		`CREATE TEMP TABLE {prefix}_pkgs AS
		 SELECT p.ecosystem,
			p.name AS pkg_name,
			-- get blob with information removed that does not affect matching
			json_set(pb.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(pb.value, '$.ranges')))
				AS pkg_blob,
			vh.provider_id,
			vh.name AS vuln_name,
			vh.id AS vulnerability_id,
			COALESCE(os.name, '') AS os_name,
			COALESCE(os.major_version, '') AS os_major,
			COALESCE(os.minor_version, '') AS os_minor,
			COALESCE(os.codename, '') AS os_codename,
			COALESCE(os.channel, '') AS os_channel,
			COALESCE(os.eoas_date, '') AS os_eoas_date
		 FROM {db}affected_package_handles aph
		 JOIN {db}vulnerability_handles vh ON aph.vulnerability_id = vh.id
		 JOIN {db}packages p ON aph.package_id = p.id
		 JOIN {db}blobs pb ON aph.blob_id = pb.id
		 LEFT JOIN {db}operating_systems os ON aph.operating_system_id = os.id
		 `,
		`CREATE INDEX idx_{prefix}_pkgs ON {prefix}_pkgs (vuln_name, provider_id, ecosystem, pkg_name, os_name, os_major, os_minor, os_channel)`,

		// CPE relationships: resolved vuln + CPE + blob
		`CREATE TEMP TABLE {prefix}_cpes AS
		 SELECT vh.name AS vuln_name,
			vh.provider_id,
			vh.id AS vulnerability_id,
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
		 `,
		`CREATE INDEX idx_{prefix}_cpes ON {prefix}_cpes (vuln_name, provider_id, part, vendor, product)`,
	}

	return d.executeTemplates(templates, r)
}

//nolint:funlen
func (d *DBDiffer) createDiffViewsPackages() error {
	r := strings.NewReplacer()

	templates := []string{
		`CREATE TEMP VIEW pkg_diff_added AS
		SELECT DISTINCT
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM new_pkgs p
		LEFT JOIN old_pkgs p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		WHERE p2.vuln_name IS NULL`,

		`CREATE TEMP VIEW pkg_diff_removed AS
		SELECT DISTINCT
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM old_pkgs p
		LEFT JOIN new_pkgs p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		WHERE p2.vuln_name IS NULL`,

		`CREATE TEMP VIEW pkg_diff_modified AS
		SELECT DISTINCT
			p.vulnerability_id,
			p.ecosystem,
			p.pkg_name,
			p.provider_id,
			p.vuln_name
		FROM old_pkgs p
		JOIN new_pkgs p2
			ON p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		WHERE NOT EXISTS(
			SELECT 1 FROM new_pkgs p2
			WHERE p.vuln_name = p2.vuln_name
			AND p.provider_id = p2.provider_id
			AND p.ecosystem = p2.ecosystem
			AND p.pkg_name = p2.pkg_name
			AND p.os_name = p2.os_name
			AND p.os_major = p2.os_major
			AND p.os_minor = p2.os_minor
			AND p.os_codename = p2.os_codename
			AND p.os_channel = p2.os_channel
		AND p.pkg_blob = p2.pkg_blob)`,

		`CREATE TEMP VIEW cpe_diff_added AS
		SELECT DISTINCT
		    c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name
		FROM new_cpes c
		LEFT JOIN old_cpes c2
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
		WHERE c2.vuln_name IS NULL`,

		`CREATE TEMP VIEW cpe_diff_removed AS
		SELECT DISTINCT
		    c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name
		FROM old_cpes c
		LEFT JOIN new_cpes c2
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
		WHERE c2.vuln_name IS NULL`,

		`CREATE TEMP VIEW cpe_diff_modified AS
		SELECT DISTINCT
			c.part, c.vendor, c.product, c.edition, c.language, c.sw_edition, c.target_hw, c.target_sw, c.other,
			c.provider_id, c.vuln_name, c.cpe_blob, c2.cpe_blob
		FROM old_cpes c
		JOIN new_cpes c2
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
		WHERE NOT EXISTS (
			SELECT 1 FROM new_cpes c2
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
			AND c.cpe_blob = c2.cpe_blob)`,
	}

	return d.executeTemplates(templates, r)
}
