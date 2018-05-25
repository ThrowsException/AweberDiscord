CREATE TABLE keys (
    aid        	varchar(256) CONSTRAINT firstkey PRIMARY KEY,
    list_id     varchar(256),
    key       	varchar(256) NOT NULL,
    secret      varchar(256) NOT NULL
);