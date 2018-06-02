CREATE TABLE keys (
    aid        	varchar(256) CONSTRAINT firstkey PRIMARY KEY,
    list_id     varchar(256),
    key       	varchar(256) NOT NULL,
    secret      varchar(256) NOT NULL
);

CREATE TABLE users (
    id              serial PRIMARY KEY,
    email           varchar NOT NULL UNIQUE,
    name            varchar NOT NULL,
    hashed_password varchar NOT NULL
);