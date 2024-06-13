-- name: CreateDatabaseSpecificNvd :one
INSERT INTO database_specific_nvd (db_specific_id, vulnStatus, cisaExploitAdd, cisaActionDue, cisaRequiredAction, cisaVulnerabilityName)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING db_specific_id;

-- name: ListDatabaseSpecificNvd :many
SELECT * FROM database_specific_nvd;
