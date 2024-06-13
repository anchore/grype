
-- name: CreateAffectedCpe :one
INSERT INTO affected_cpes (vulnerability_id, type, vendor, product, version, "update", target_software)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING affected_id;

-- name: ListAffectedCPEsByProduct :many
SELECT * FROM affected_cpes
WHERE product = ?;

-- name: ListAffectedCPEsByProductAndVendor :many
SELECT * FROM affected_cpes
WHERE product = ?
  AND vendor = ?
ORDER BY product, vendor;

-- name: ListAffectedCPEsByProductAndVendorAndVersion :many
SELECT * FROM affected_cpes
WHERE product = ?
  AND vendor = ?
  AND version = ?
ORDER BY product, vendor, version;