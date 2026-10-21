package diff

import (
	"fmt"
	"strings"
)

// createDiffKeyTablesPackages builds key tables shared by both databases, which assign the same integer key to
// equivalent vulnerabilities (name + provider), packages (ecosystem + name), operating systems, and CPEs in either
// database. The key is the rowid of the key table.
func (d *DBDiffer) createDiffKeyTablesPackages() error {
	templates := []string{
		`CREATE TEMP TABLE diff_vuln_keys AS
		 SELECT name, provider_id FROM main.vulnerability_handles
		 UNION
		 SELECT name, provider_id FROM new_db.vulnerability_handles`,
		`CREATE INDEX idx_diff_vuln_keys ON diff_vuln_keys (name, provider_id)`,

		`CREATE TEMP TABLE diff_pkg_keys AS
		 SELECT ecosystem, name FROM main.packages
		 UNION
		 SELECT ecosystem, name FROM new_db.packages`,
		`CREATE INDEX idx_diff_pkg_keys ON diff_pkg_keys (ecosystem, name)`,

		`CREATE TEMP TABLE diff_os_keys AS
		 SELECT '' AS name, '' AS major, '' AS minor, '' AS codename, '' AS channel -- for packages without an OS
		 UNION
		 SELECT COALESCE(name, ''), COALESCE(major_version, ''), COALESCE(minor_version, ''), COALESCE(codename, ''), COALESCE(channel, '') FROM main.operating_systems
		 UNION
		 SELECT COALESCE(name, ''), COALESCE(major_version, ''), COALESCE(minor_version, ''), COALESCE(codename, ''), COALESCE(channel, '') FROM new_db.operating_systems`,
		`CREATE INDEX idx_diff_os_keys ON diff_os_keys (name, major, minor, codename, channel)`,

		`CREATE TEMP TABLE diff_cpe_keys AS
		 SELECT part, vendor, product, edition, language, software_edition, target_hardware, target_software, other FROM main.cpes
		 UNION
		 SELECT part, vendor, product, edition, language, software_edition, target_hardware, target_software, other FROM new_db.cpes`,
		`CREATE INDEX idx_diff_cpe_keys ON diff_cpe_keys (part, vendor, product, edition, language, software_edition, target_hardware, target_software, other)`,
	}

	return d.executeTemplates(templates, strings.NewReplacer())
}

// createDiffTablesPackages builds indexed temp tables from the given schema (main or new_db)
// with the given suffix (old or new) for table names.
//
// Performance notes:
//   - the package / CPE tables only contain integer keys (see createDiffKeyTablesPackages), which are much
//     cheaper to index and compare than the strings they represent
//   - the package / CPE tables only carry the blob_id; blob content is only fetched and compared when looking
//     for modifications (see blobsEquivalent)
//   - handle tables are joined with CROSS JOIN to force sqlite to scan the handles sequentially and do
//     lookups into the other tables, rather than scanning packages / cpes and doing random index lookups into
//     the (much larger) handle tables
//   - affected and unaffected rows are combined with UNION ALL since all consumers deduplicate
//   - handles without a blob are excluded (as with the vulnerability tables), since their content can't be compared
//   - indexes include every column used by the diff views so the views are answered from the index alone
//
//nolint:funlen
func (d *DBDiffer) createDiffTablesPackages(db, schema string) error {
	r := strings.NewReplacer("{suffix}", db, "{db}", schema+".")

	templates := []string{
		// maps from database IDs to shared keys; IS is used rather than = so nulls map to the same key
		`CREATE TEMP TABLE diff_vuln_map_{suffix} AS
		 SELECT vh.id AS vulnerability_id,
			k.rowid AS vuln_key,
			CASE WHEN LOWER(vh.status) IN ('withdrawn', 'rejected') THEN 0 ELSE 1 END AS status -- 0: not vulnerable
		 FROM {db}vulnerability_handles vh
		 CROSS JOIN diff_vuln_keys k ON k.name = vh.name AND k.provider_id = vh.provider_id`,
		`CREATE INDEX idx_diff_vuln_map_{suffix} ON diff_vuln_map_{suffix} (vulnerability_id, vuln_key, status)`,

		`CREATE TEMP TABLE diff_pkg_map_{suffix} AS
		 SELECT p.id AS package_id, k.rowid AS pkg_key
		 FROM {db}packages p
		 CROSS JOIN diff_pkg_keys k ON k.ecosystem IS p.ecosystem AND k.name IS p.name`,
		`CREATE INDEX idx_diff_pkg_map_{suffix} ON diff_pkg_map_{suffix} (package_id, pkg_key)`,

		`CREATE TEMP TABLE diff_os_map_{suffix} AS
		 SELECT os.id AS operating_system_id, k.rowid AS os_key
		 FROM {db}operating_systems os
		 CROSS JOIN diff_os_keys k
			ON k.name = COALESCE(os.name, '')
			AND k.major = COALESCE(os.major_version, '')
			AND k.minor = COALESCE(os.minor_version, '')
			AND k.codename = COALESCE(os.codename, '')
			AND k.channel = COALESCE(os.channel, '')`,
		`CREATE INDEX idx_diff_os_map_{suffix} ON diff_os_map_{suffix} (operating_system_id, os_key)`,

		`CREATE TEMP TABLE diff_cpe_map_{suffix} AS
		 SELECT c.id AS cpe_id, k.rowid AS cpe_key
		 FROM {db}cpes c
		 CROSS JOIN diff_cpe_keys k
			ON k.part IS c.part
			AND k.vendor IS c.vendor
			AND k.product IS c.product
			AND k.edition IS c.edition
			AND k.language IS c.language
			AND k.software_edition IS c.software_edition
			AND k.target_hardware IS c.target_hardware
			AND k.target_software IS c.target_software
			AND k.other IS c.other`,
		`CREATE INDEX idx_diff_cpe_map_{suffix} ON diff_cpe_map_{suffix} (cpe_id, cpe_key)`,

		// package + language/os + vulnerability
		`CREATE TEMP TABLE diff_pkg_{suffix} AS
		 SELECT vm.vuln_key,
			pm.pkg_key,
			COALESCE(om.os_key, (SELECT rowid FROM diff_os_keys WHERE name = '' AND major = '' AND minor = '' AND codename = '' AND channel = '')) AS os_key,
			vm.status,
			aph.blob_id
		 FROM {db}affected_package_handles aph
		 CROSS JOIN diff_vuln_map_{suffix} vm ON vm.vulnerability_id = aph.vulnerability_id
		 CROSS JOIN diff_pkg_map_{suffix} pm ON pm.package_id = aph.package_id
		 LEFT JOIN diff_os_map_{suffix} om ON om.operating_system_id = aph.operating_system_id
		 WHERE EXISTS (SELECT 1 FROM {db}blobs b WHERE b.id = aph.blob_id)
		 UNION ALL
		 SELECT vm.vuln_key,
			pm.pkg_key,
			COALESCE(om.os_key, (SELECT rowid FROM diff_os_keys WHERE name = '' AND major = '' AND minor = '' AND codename = '' AND channel = '')) AS os_key,
			0 AS status, -- unaffected records are always a not-vulnerable status
			aph.blob_id
		 FROM {db}unaffected_package_handles aph
		 CROSS JOIN diff_vuln_map_{suffix} vm ON vm.vulnerability_id = aph.vulnerability_id
		 CROSS JOIN diff_pkg_map_{suffix} pm ON pm.package_id = aph.package_id
		 LEFT JOIN diff_os_map_{suffix} om ON om.operating_system_id = aph.operating_system_id
		 WHERE EXISTS (SELECT 1 FROM {db}blobs b WHERE b.id = aph.blob_id)
		 `,
		`CREATE INDEX idx_pkg_{suffix} ON diff_pkg_{suffix} (vuln_key, pkg_key, os_key, status, blob_id)`,

		// CPE relationships: vuln + CPE + blob
		`CREATE TEMP TABLE diff_cpe_{suffix} AS
		 SELECT vm.vuln_key,
			cm.cpe_key,
			vm.status,
			ach.blob_id
		 FROM {db}affected_cpe_handles ach
		 CROSS JOIN diff_vuln_map_{suffix} vm ON vm.vulnerability_id = ach.vulnerability_id
		 CROSS JOIN diff_cpe_map_{suffix} cm ON cm.cpe_id = ach.cpe_id
		 WHERE EXISTS (SELECT 1 FROM {db}blobs b WHERE b.id = ach.blob_id)
		 UNION ALL
		 SELECT vm.vuln_key,
			cm.cpe_key,
			0 AS status, -- unaffected records are always a not-vulnerable status
			ach.blob_id
		 FROM {db}unaffected_cpe_handles ach
		 CROSS JOIN diff_vuln_map_{suffix} vm ON vm.vulnerability_id = ach.vulnerability_id
		 CROSS JOIN diff_cpe_map_{suffix} cm ON cm.cpe_id = ach.cpe_id
		 WHERE EXISTS (SELECT 1 FROM {db}blobs b WHERE b.id = ach.blob_id)
		 `,
		`CREATE INDEX idx_cpe_{suffix} ON diff_cpe_{suffix} (vuln_key, cpe_key, status, blob_id)`,
	}

	return d.executeTemplates(templates, r)
}

const (
	pkgKeyMatch = `a.vuln_key = b.vuln_key AND a.pkg_key = b.pkg_key AND a.os_key = b.os_key`
	cpeKeyMatch = `a.vuln_key = b.vuln_key AND a.cpe_key = b.cpe_key`

	// pkgResult resolves the keys of the distinct changed rows back to the values they represent
	pkgResult = `SELECT pk.ecosystem, pk.name AS pkg_name, vk.provider_id, vk.name AS vuln_name
		FROM (%s) d
		CROSS JOIN diff_vuln_keys vk ON vk.rowid = d.vuln_key
		CROSS JOIN diff_pkg_keys pk ON pk.rowid = d.pkg_key`

	cpeResult = `SELECT ck.part, ck.vendor, ck.product, ck.edition, ck.language, ck.software_edition AS sw_edition,
			ck.target_hardware AS target_hw, ck.target_software AS target_sw, ck.other, vk.provider_id, vk.name AS vuln_name
		FROM (%s) d
		CROSS JOIN diff_vuln_keys vk ON vk.rowid = d.vuln_key
		CROSS JOIN diff_cpe_keys ck ON ck.rowid = d.cpe_key`
)

// blobsEquivalent compares the old (a) and new (b) blobs, ignoring information that does not affect matching.
// most blobs are unchanged between databases, so the raw values are compared first to avoid the comparatively
// expensive JSON normalization
func blobsEquivalent() string {
	return fmt.Sprintf(`(
				(SELECT ob.value FROM main.blobs ob WHERE ob.id = a.blob_id) = (SELECT nb.value FROM new_db.blobs nb WHERE nb.id = b.blob_id)
				OR (SELECT %s FROM main.blobs ob WHERE ob.id = a.blob_id) = (SELECT %s FROM new_db.blobs nb WHERE nb.id = b.blob_id)
			)`, normalizedBlob("ob"), normalizedBlob("nb"))
}

// normalizedBlob returns the value of the blob with the given alias with information removed that does not affect matching
func normalizedBlob(alias string) string {
	return fmt.Sprintf(`json_set(%[1]s.value,'$.ranges',(SELECT json_group_array(json_remove(value, '$.fix.detail.available')) FROM json_each(%[1]s.value, '$.ranges')))`, alias)
}

func (d *DBDiffer) createDiffViewsPackages() error {
	r := strings.NewReplacer("{pkgKeyMatch}", pkgKeyMatch, "{cpeKeyMatch}", cpeKeyMatch, "{blobsEquivalent}", blobsEquivalent())

	// presence summarizes, for each key, whether the old and new databases have records with a vulnerable (1) or
	// not-vulnerable (0) status, keeping only the keys that were added or removed. Both tables have an index ordered
	// by key, so sqlite merges the two indexes in a single pass rather than probing one table for each row of the other
	presence := `CREATE TEMP TABLE diff_{type}_presence AS
		SELECT vuln_key, {key},
			MAX(side = 0 AND status = 0) AS o0, MAX(side = 0 AND status = 1) AS o1,
			MAX(side = 1 AND status = 0) AS n0, MAX(side = 1 AND status = 1) AS n1
		FROM (
			SELECT {cols}, status, 0 AS side FROM diff_{type}_old
			UNION ALL
			SELECT {cols}, status, 1 AS side FROM diff_{type}_new
			ORDER BY {cols}
		)
		GROUP BY {cols}
		HAVING NOT ((o0 OR o1) AND (n0 OR n1)) OR (n1 AND o0) OR (o1 AND n0)`

	// "added" / "removed" rows are records with no matching record on the other side, or which are vulnerable
	// where a matching record on the other side is not
	added := `SELECT DISTINCT vuln_key, {key} FROM diff_{type}_presence WHERE (n0 OR n1) AND (NOT (o0 OR o1) OR (n1 AND o0))`
	removed := `SELECT DISTINCT vuln_key, {key} FROM diff_{type}_presence WHERE (o0 OR o1) AND (NOT (n0 OR n1) OR (o1 AND n0))`

	// "modified" rows are records where a record with the same key and status exists on the other side, but none of
	// these have equivalent blob content
	modified := `SELECT DISTINCT a.vuln_key, a.{key}
		FROM diff_{type}_old a
		WHERE EXISTS (SELECT 1 FROM diff_{type}_new b WHERE {keyMatch} AND a.status = b.status)
		AND NOT EXISTS (
			SELECT 1 FROM diff_{type}_new b
			WHERE {keyMatch}
			AND a.status = b.status
			AND {blobsEquivalent}
		)`

	pkg := strings.NewReplacer("{type}", "pkg", "{key}", "pkg_key", "{keyMatch}", "{pkgKeyMatch}", "{cols}", "vuln_key, pkg_key, os_key")
	cpe := strings.NewReplacer("{type}", "cpe", "{key}", "cpe_key", "{keyMatch}", "{cpeKeyMatch}", "{cols}", "vuln_key, cpe_key")

	templates := []string{
		pkg.Replace(presence),
		cpe.Replace(presence),
		`CREATE TEMP VIEW diff_pkg_added AS ` + fmt.Sprintf(pkgResult, pkg.Replace(added)),
		`CREATE TEMP VIEW diff_pkg_removed AS ` + fmt.Sprintf(pkgResult, pkg.Replace(removed)),
		`CREATE TEMP VIEW diff_pkg_modified AS ` + fmt.Sprintf(pkgResult, pkg.Replace(modified)),
		`CREATE TEMP VIEW diff_cpe_added AS ` + fmt.Sprintf(cpeResult, cpe.Replace(added)),
		`CREATE TEMP VIEW diff_cpe_removed AS ` + fmt.Sprintf(cpeResult, cpe.Replace(removed)),
		`CREATE TEMP VIEW diff_cpe_modified AS ` + fmt.Sprintf(cpeResult, cpe.Replace(modified)),
	}

	return d.executeTemplates(templates, r)
}
