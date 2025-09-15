
-- name: CreateUser :one
Insert into  users(id,created_at,updated_at,email,hashed_password) VALUES(
     gen_random_uuid(),
    Now(),
     Now(),
     $1,
     $2)

RETURNING *;


-- name: GetUser :one
SELECT * from users
WHERE email = $1;