CREATE TABLE "user" (
    id              uuid PRIMARY KEY,
    email           text NOT NULL UNIQUE,
    hashed_password text NOT NULL,
    full_name       text,
    is_active       boolean NOT NULL DEFAULT true,
    created_at      timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    updated_at      timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE INDEX ix_user_email     ON "user" (email);
CREATE INDEX ix_user_full_name ON "user" (full_name);

CREATE TABLE user_group (
    id   uuid PRIMARY KEY,
    name text NOT NULL UNIQUE
);

CREATE INDEX ix_user_group_name ON user_group (name);

CREATE TABLE user_group_user (
    user_id       uuid NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    user_group_id uuid NOT NULL REFERENCES user_group (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, user_group_id)
);

CREATE TABLE refresh_token (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES "user" (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamp NOT NULL,
    revoked    boolean NOT NULL DEFAULT false,
    created_at timestamp NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE INDEX ix_refresh_token_user_id    ON refresh_token (user_id);
CREATE INDEX ix_refresh_token_token_hash ON refresh_token (token_hash);
