-- name: CreateDatabaseSpecific :one
INSERT INTO database_specific (entity_type)
VALUES (?)
RETURNING db_specific_id;

-- name: ListDatabaseSpecific :many
SELECT * FROM database_specific;
