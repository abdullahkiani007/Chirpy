-- name: CreateChirp :one
INSERT INTO chirp(id,created_at,updated_at,user_id,body) VALUES(
    gen_random_uuid(),
    Now(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirp
ORDER BY created_at;


-- name: GetChirp :one
SELECT * FROM chirp
Where id = $1;