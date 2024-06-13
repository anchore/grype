-- name: CreateDbMetadata :one
INSERT INTO db_metadata (build_timestamp, schema_version)
VALUES (?, ?)
RETURNING *;

-- name: CreateProvider :one
INSERT INTO providers (name, version, date_captured, input_digest, data_oci_repository)
VALUES (?, ?, ?, ?, ?)
RETURNING provider_id;

-- name: CreateVulnerability :one
INSERT INTO vulnerabilities (provider_id, id, modified, published, withdrawn, summary_digest, detail_digest, database_specific_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING vulnerability_id;

-- name: CreateAlias :one
INSERT INTO aliases (vulnerability_id, alias)
VALUES (?, ?)
RETURNING alias_id;

-- name: CreateRelatedVulnerability :one
INSERT INTO related_vulnerabilities (vulnerability_id, related_vulnerability_id)
VALUES (?, ?)
RETURNING related_id;

-- name: CreateSeverity :one
INSERT INTO severities (vulnerability_id, type, score, source, tag)
VALUES (?, ?, ?, ?, ?)
RETURNING severity_id;

-- name: CreatePackageQualifier :one
INSERT INTO package_qualifiers (affected_id, entity_type)
VALUES (?, ?)
RETURNING qualifier_id;

-- name: CreatePackageQualifierPlatformCpe :one
INSERT INTO package_qualifier_platform_cpes (qualifier_id, cpe)
VALUES (?, ?)
RETURNING qualifier_id;

-- name: CreatePackageQualifierRpmModularity :one
INSERT INTO package_qualifier_rpm_modularities (qualifier_id, module)
VALUES (?, ?)
RETURNING qualifier_id;

-- name: CreateAffected :one
INSERT INTO affected (entity_type)
VALUES (?)
RETURNING affected_id;

-- name: CreateLogicalPackage :one
INSERT INTO logical_package (logical_package_id, affected_id)
VALUES (?, ?)
RETURNING logical_package_id;

-- name: CreatePackageDigest :one
INSERT INTO package_digests (vulnerability_id, digest_algorithm, digest_value)
VALUES (?, ?, ?)
RETURNING *;

-- name: CreateAffectedVersion :one
INSERT INTO affected_versions (affected_id, version)
VALUES (?, ?)
RETURNING affected_id;

-- name: CreateNotAffectedVersion :one
INSERT INTO not_affected_versions (affected_id, version)
VALUES (?, ?)
RETURNING affected_id;

-- name: CreateAffectedSeverity :one
INSERT INTO affected_severities (affected_id, type, score, source, tag)
VALUES (?, ?, ?, ?, ?)
RETURNING affected_id;

-- name: CreateRangeEvent :one
INSERT INTO range_events (affected_id, type, repo, introduced, fixed, last_affected, limit, state)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING event_id;

-- name: CreateReference :one
INSERT INTO "references" (vulnerability_id, type, url)
VALUES (?, ?, ?)
RETURNING reference_id;


-- TODO: another DB? maybe via an attachment?
-- -- name: CreateDescription :one
-- INSERT INTO descriptions (digest, value)
-- VALUES (?, ?)
-- RETURNING *;
