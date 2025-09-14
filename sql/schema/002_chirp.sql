-- +goose Up
CREATE TABLE chirp(
    id UUID Primary Key,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id  UUID NOT NULL,
    CONSTRAINT fk_user_id FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL
);


-- +goose Down
DROP TABLE chirp;