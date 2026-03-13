CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users (resource owners)
CREATE TABLE IF NOT EXISTS public.users
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    email text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT email_unique UNIQUE (email)
);

-- OAuth 2.1 clients (registered via Dynamic Client Registration)
CREATE TABLE IF NOT EXISTS public.oauth_clients
(
    client_id text NOT NULL,
    client_secret text,
    client_name text,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    grant_types text[] NOT NULL DEFAULT '{authorization_code}',
    response_types text[] NOT NULL DEFAULT '{code}',
    token_endpoint_auth_method text NOT NULL DEFAULT 'none',
    scope text NOT NULL DEFAULT '',
    client_id_issued_at bigint NOT NULL,
    client_secret_expires_at bigint NOT NULL DEFAULT 0,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT oauth_clients_pkey PRIMARY KEY (client_id)
);

-- Authorization codes (short-lived, single-use)
CREATE TABLE IF NOT EXISTS public.authorization_codes
(
    code text NOT NULL,
    client_id text NOT NULL REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scope text NOT NULL DEFAULT '',
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL DEFAULT 'S256',
    expires_at timestamp with time zone NOT NULL,
    used boolean NOT NULL DEFAULT false,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT authorization_codes_pkey PRIMARY KEY (code)
);

-- Refresh tokens (long-lived, rotatable)
CREATE TABLE IF NOT EXISTS public.refresh_tokens
(
    token text NOT NULL,
    client_id text NOT NULL REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    scope text NOT NULL DEFAULT '',
    expires_at timestamp with time zone NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token)
);
