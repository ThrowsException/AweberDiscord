CREATE TABLE users (
    id              serial PRIMARY KEY,
    email           varchar NOT NULL UNIQUE,
    name            varchar NOT NULL,
    hashed_password varchar NOT NULL,
    channel_id      varchar,
    list_id      varchar
);

CREATE TABLE keys (
    aid        	varchar(256) CONSTRAINT firstkey PRIMARY KEY,
    list_id     varchar(256),
    key       	varchar(256) NOT NULL,
    secret      varchar(256) NOT NULL,
    user_id     integer REFERENCES users NOT NULL,
    guild_id    varchar
);
