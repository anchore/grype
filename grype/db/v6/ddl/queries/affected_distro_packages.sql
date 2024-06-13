-- name: CreateAffectedDistroPackage :one
INSERT INTO affected_distro_packages (affected_id, vulnerability_id, package_name, os_id)
VALUES (?, ?, ?, ?)
RETURNING affected_id;

-- name: ListAffectedDistroPackagesByPackageNameAndOsMajorMinorVersion :many
SELECT adp.*, os.name, os.major_version, os.minor_version
FROM affected_distro_packages adp
         JOIN operating_systems os ON adp.os_id = os.os_id
WHERE adp.package_name = ?
  AND os.name = ?
  AND os.major_version = ?
  AND os.minor_version = ?;
