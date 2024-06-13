-- name: CreateOperatingSystem :one
INSERT INTO operating_systems (name, major_version, minor_version, codename)
VALUES (?, ?, ?, ?)
RETURNING os_id;

-- TODO: this ends up creating interface{} values for input params, which is not great at runtime safety-wise... but this is a single flex statement, replacing all of the other ones below
-- -- name: ListOperatingSystems :many
-- SELECT * FROM operating_systems
-- WHERE (name = COALESCE(NULLIF(@name, ''), name))
--   AND (major_version = COALESCE(NULLIF(@major_version, ''), major_version))
--   AND (minor_version = COALESCE(?, minor_version))
--   AND (codename = COALESCE(?, codename))
-- ORDER BY name, major_version, minor_version;

-- name: ListOperatingSystems :many
SELECT * FROM operating_systems
ORDER BY name, major_version, minor_version;

-- name: ListOperatingSystemsByName :many
SELECT * FROM operating_systems
WHERE name = ?
ORDER BY name, major_version, minor_version;

-- name: ListOperatingSystemsByNameAndMajorVersion :many
SELECT * FROM operating_systems
WHERE name = ?
  AND major_version = ?
ORDER BY name, major_version, minor_version;

-- name: ListOperatingSystemsByNameAndExactVersion :many
SELECT * FROM operating_systems
WHERE name = ?
  AND major_version = ?
  AND minor_version = ?
ORDER BY name, major_version, minor_version;

-- name: ListOperatingSystemsByCodename :many
SELECT * FROM operating_systems
WHERE codename = ?
ORDER BY name, major_version, minor_version;
