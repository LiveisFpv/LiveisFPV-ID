CREATE TABLE IF NOT EXISTS users
(
    id           SERIAL PRIMARY KEY,
    first_name  TEXT    NOT NULL,
    last_name   TEXT    NOT NULL,
    email        TEXT    NOT NULL UNIQUE,
    email_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    pass_hash    BYTEA  ,
    google_id   TEXT    UNIQUE,
    yandex_id   TEXT    UNIQUE,
    vk_id      TEXT    UNIQUE,
    photo       TEXT,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    roles        TEXT[]   NOT NULL DEFAULT '{"USER"}',
    locale       TEXT    NOT NULL DEFAULT 'ru',
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_google_id ON users (google_id);
CREATE INDEX IF NOT EXISTS idx_yandex_id ON users (yandex_id);
CREATE INDEX IF NOT EXISTS idx_vk_id ON users (vk_id);