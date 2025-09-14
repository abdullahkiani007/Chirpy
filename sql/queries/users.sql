
-- name: CreateUser :one
Insert into  users(id,created_at,updated_at,email) VALUES(
     gen_random_uuid(),
    Now(),
     Now(),
     $1)

RETURNING *;