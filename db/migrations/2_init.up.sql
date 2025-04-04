DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users
(
    id           SERIAL PRIMARY KEY,
    email        TEXT    NOT NULL UNIQUE,
    pass_hash    BYTEA    NOT NULL,
    yandex_token BYTEA
);
CREATE INDEX IF NOT EXISTS idx_email ON users (email);