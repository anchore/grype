-- name: CreateAffectedPackage :one
INSERT INTO affected_packages (vulnerability_id, ecosystem, package_name, purl)
VALUES (?, ?, ?, ?)
RETURNING affected_id;

-- name: ListAffectedPackagesByPackageName :many
SELECT * FROM affected_packages
WHERE package_name = ?;

-- name: ListAffectedPackagesByPackageNameAndEcosystem :many
SELECT * FROM affected_packages
WHERE package_name = ?
  AND ecosystem = ?
ORDER BY package_name, ecosystem;
