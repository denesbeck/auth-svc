CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS public.users
(
    uuid uuid NOT NULL DEFAULT uuid_generate_v4(),
    email text NOT NULL,
    salt text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT users_pkey PRIMARY KEY (uuid),
    CONSTRAINT email_unique UNIQUE (email)
);
