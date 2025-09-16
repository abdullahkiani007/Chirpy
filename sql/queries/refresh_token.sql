-- name: CreateToken :one
INSERT INTO refresh_token (token,created_at,updated_at,user_id,expires_at) VALUES(
    $1,Now(),Now(),$2,$3
)

RETURNING *;


-- name: RevokeToken :one
UPDATE refresh_token
set revoked_at = Now(), updated_at = Now()
WHERE token = $1

RETURNING *;

-- name: GetToken :one
SELECT * FROM refresh_token
WHERE token = $1 AND revoked_at is NULL;


-- name: GetUserFromRefreshToken :one
SELECT user_id from refresh_token
WHERE token = $1 AND revoked_at is NULL AND expires_at > NOW();