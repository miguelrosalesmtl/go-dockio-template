-- The schema of a multi-tenant application whose identity manager is døckio.
--
-- What lives here, and what does not:
--
--   users              A local row per døckio account the application has seen,
--                      plus the local break-glass superusers. Only a superuser has
--                      a password, and every superuser has one: that is the only
--                      local credential in the system. Email is a copy, never an
--                      identifier.
--   oidc_identities    Links a user to a døckio account by (issuer, uid). Never by
--                      sub, username or email: all three can change.
--   organizations      The tenants. Each one's people, roles and groups live in
--                      its døckio realm (dockio_realm), not here.
--   sessions           Server-side sessions. A døckio session also records which
--                      døckio session (sid) and account (uid) it belongs to, so a
--                      back-channel logout can find it, and the sealed id token,
--                      so sign-out can end the døckio session too.
--   api_keys           Programmatic credentials per organization, scoped by the
--                      permission catalog.
--   audit_log          Append-only, enforced by triggers.
--   oidc_settings      The ONE OIDC connection for the whole installation.
--   oidc_connect_attempts  One row per Quick connect click (SOIDC v1 §14).
--   oidc_login_attempts    One row per "Continue with døckio" click.
--
-- There are no membership, role, invitation, password-reset or email-verification
-- tables, by design: døckio owns all of that. docs/dockio.md explains the split.

-- +goose Up

--
-- PostgreSQL database dump
--


-- Dumped from database version 18.4
-- Dumped by pg_dump version 18.4


--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: audit_log_is_append_only(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_is_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Exactly ONE update is permitted, and it is not really a content change:
        -- audit_log.actor_user_id is ON DELETE SET NULL, so hard-deleting a user
        -- anonymises their entries rather than destroying them. That is deliberate,
        -- and it is how a right-to-erasure request is served without losing the
        -- record that the actions happened at all.
        --
        -- A blanket "no UPDATE" would make deleting a user impossible forever. So
        -- allow the anonymisation, and ONLY the anonymisation: every other column
        -- must be byte-for-byte identical, and actor_user_id may only go from set
        -- to NULL -- never the reverse, and never to somebody else.
        IF OLD.actor_user_id IS NOT NULL
           AND NEW.actor_user_id IS NULL
           AND NEW.id          =              OLD.id
           AND NEW.organization_id   IS NOT DISTINCT FROM OLD.organization_id
           AND NEW.action      =              OLD.action
           AND NEW.target_type =              OLD.target_type
           AND NEW.target_id   =              OLD.target_id
           AND NEW.metadata    =              OLD.metadata
           AND NEW.request_id  =              OLD.request_id
           AND NEW.ip_address  IS NOT DISTINCT FROM OLD.ip_address
           AND NEW.user_agent  =              OLD.user_agent
           AND NEW.created_at  =              OLD.created_at
        THEN
            RETURN NEW;
        END IF;

        RAISE EXCEPTION 'audit_log is append-only: rows cannot be modified'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    -- DELETE is allowed only to deliberate audit maintenance, which announces
    -- itself by setting this GUC for the duration of its transaction:
    --
    --   * the retention sweep (`server purge`), and
    --   * a hard delete of an organization, which cascades into its entries.
    --
    -- Note the consequence, and it is intended: hard-deleting an organization takes its
    -- audit trail with it. The APPLICATION never does this -- it soft-deletes,
    -- which destroys nothing. A hard delete is an out-of-band act and has to look
    -- like one.
    --
    -- AND NOTE THE LIMIT: any role can set this GUC. This stops an ACCIDENT, not an
    -- ADVERSARY -- code already running as the app can set it and delete. Real
    -- tamper-resistance needs a second, restricted DB identity; see internal/audit.
    IF TG_OP = 'DELETE'
       AND coalesce(current_setting('app.audit_purge', true), 'off') <> 'on' THEN
        RAISE EXCEPTION 'audit_log is append-only: rows cannot be deleted except by the retention sweep'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN OLD; -- permit the DELETE
END;
$$;
-- +goose StatementEnd


--
-- Name: audit_log_no_truncate(); Type: FUNCTION; Schema: public; Owner: -
--

-- +goose StatementBegin
CREATE FUNCTION public.audit_log_no_truncate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: it cannot be truncated'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
-- +goose StatementEnd




--
-- Name: api_key_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_key_permissions (
    api_key_id uuid NOT NULL,
    permission text NOT NULL
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    token_hash bytea NOT NULL,
    token_prefix text NOT NULL,
    created_by uuid NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT uuidv7() NOT NULL,
    organization_id uuid,
    actor_user_id uuid,
    action text NOT NULL,
    target_type text DEFAULT ''::text NOT NULL,
    target_id text DEFAULT ''::text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    request_id text DEFAULT ''::text NOT NULL,
    ip_address inet,
    user_agent text DEFAULT ''::text NOT NULL
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT uuidv7() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    dockio_realm text
);


--
-- Name: permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permissions (
    key text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id uuid DEFAULT uuidv7() NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    user_agent text DEFAULT ''::text NOT NULL,
    ip_address inet,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_method text DEFAULT 'password'::text NOT NULL,
    dockio_uid text,
    dockio_sid text,
    dockio_realms text[] DEFAULT '{}'::text[] NOT NULL,
    id_token_enc bytea,
    CONSTRAINT sessions_auth_method_check CHECK ((auth_method = ANY (ARRAY['password'::text, 'dockio'::text]))),
    CONSTRAINT sessions_dockio_has_uid CHECK (((auth_method <> 'dockio'::text) OR (dockio_uid IS NOT NULL)))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT uuidv7() NOT NULL,
    email public.citext,
    password_hash text,
    first_name text DEFAULT ''::text NOT NULL,
    last_name text DEFAULT ''::text NOT NULL,
    is_superuser boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT users_password_iff_superuser CHECK (((password_hash IS NOT NULL) = is_superuser))
);


--
-- Name: api_key_permissions api_key_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_pkey PRIMARY KEY (api_key_id, permission);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_token_hash_key UNIQUE (token_hash);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (key);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: api_keys_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_organization_id_idx ON public.api_keys USING btree (organization_id) WHERE (revoked_at IS NULL);


--
-- Name: audit_log_global_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_global_idx ON public.audit_log USING btree (id DESC) WHERE (organization_id IS NULL);


--
-- Name: audit_log_organization_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_action_idx ON public.audit_log USING btree (organization_id, action, id DESC);


--
-- Name: audit_log_organization_actor_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_actor_idx ON public.audit_log USING btree (organization_id, actor_user_id, id DESC);


--
-- Name: audit_log_organization_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_organization_id_idx ON public.audit_log USING btree (organization_id, id DESC);


--
-- Name: organizations_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organizations_deleted_at_idx ON public.organizations USING btree (deleted_at) WHERE (deleted_at IS NULL);


--
-- Name: organizations_live_slug_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organizations_live_slug_idx ON public.organizations USING btree (slug) WHERE (deleted_at IS NULL);


--
-- Name: sessions_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_expires_at_idx ON public.sessions USING btree (expires_at);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_idx ON public.sessions USING btree (user_id);


--
-- Name: audit_log audit_log_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_append_only BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.audit_log_is_append_only();


--
-- Name: audit_log audit_log_no_truncate; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON public.audit_log FOR EACH STATEMENT EXECUTE FUNCTION public.audit_log_no_truncate();


--
-- Name: api_key_permissions api_key_permissions_api_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES public.api_keys(id) ON DELETE CASCADE;


--
-- Name: api_key_permissions api_key_permissions_permission_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_key_permissions
    ADD CONSTRAINT api_key_permissions_permission_fkey FOREIGN KEY (permission) REFERENCES public.permissions(key) ON DELETE RESTRICT;


--
-- Name: api_keys api_keys_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: audit_log audit_log_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

-- ---------------------------------------------------------------- døckio

CREATE UNIQUE INDEX users_superuser_email_idx ON public.users USING btree (email) WHERE is_superuser;
CREATE UNIQUE INDEX organizations_dockio_realm_idx ON public.organizations USING btree (dockio_realm) WHERE (dockio_realm IS NOT NULL);
CREATE INDEX sessions_dockio_uid_idx ON public.sessions USING btree (dockio_uid) WHERE (dockio_uid IS NOT NULL);
CREATE INDEX sessions_dockio_sid_idx ON public.sessions USING btree (dockio_sid) WHERE (dockio_sid IS NOT NULL);

CREATE TABLE oidc_identities (
    id         uuid DEFAULT uuidv7() PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issuer     text NOT NULL, -- the TENANT issuer, e.g. https://døck.io/t/acme
    uid        text NOT NULL, -- the døckio account id; never changes
    username   text NOT NULL, -- copy only; the person can rename themselves
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oidc_identities_issuer_uid_key UNIQUE (issuer, uid)
);

CREATE INDEX oidc_identities_user_id_idx ON oidc_identities (user_id);

CREATE TABLE oidc_settings (
    id                smallint PRIMARY KEY DEFAULT 1,
    issuer            text NOT NULL,
    client_id         text NOT NULL,
    client_secret_enc bytea NOT NULL, -- sealed; never leaves the server
    enabled           boolean NOT NULL DEFAULT false,

    -- The Quick connect fields. All NULL for a connection set up by hand.
    connection_id     text,
    tenant_name       text,
    tenant_address    text,
    home_realm        text,
    manage_uri        text,
    secret_expires_at timestamptz,
    -- Truncated to the second: the revocation notice's iat has one-second
    -- resolution, and the replay rule compares the two.
    connected_at      timestamptz,
    connected_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    revoked_at        timestamptz,

    catalog_version   bigint,
    catalog_synced_at timestamptz,

    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT oidc_settings_single_row CHECK (id = 1),
    CONSTRAINT oidc_settings_connected_at CHECK (connection_id IS NULL OR connected_at IS NOT NULL)
);

CREATE TABLE oidc_connect_attempts (
    id                uuid DEFAULT uuidv7() PRIMARY KEY,
    state_hash        bytea NOT NULL UNIQUE, -- sha256(state); never the state itself
    code_verifier_enc bytea NOT NULL,        -- sealed like the client secret
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    station_url       text NOT NULL,
    public_url        text NOT NULL,
    renew             boolean NOT NULL DEFAULT false,
    connection_id     text,                  -- set when renew
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL
);

CREATE INDEX oidc_connect_attempts_expires_at_idx ON oidc_connect_attempts (expires_at);

-- ---------------------------------------------------------------- sign-in attempts

CREATE TABLE oidc_login_attempts (
    id                uuid DEFAULT uuidv7() PRIMARY KEY,
    state_hash        bytea NOT NULL UNIQUE,
    nonce             text NOT NULL,
    code_verifier_enc bytea NOT NULL,
    realm             text,                  -- set when started from /b/{organization}
    return_to         text NOT NULL DEFAULT '/',
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL
);

CREATE INDEX oidc_login_attempts_expires_at_idx ON oidc_login_attempts (expires_at);

-- +goose Down
DROP TABLE IF EXISTS public.oidc_login_attempts, public.oidc_connect_attempts, public.oidc_settings,
    public.oidc_identities, public.api_key_permissions, public.api_keys, public.audit_log,
    public.organizations, public.permissions, public.sessions, public.users CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_is_append_only() CASCADE;
DROP FUNCTION IF EXISTS public.audit_log_no_truncate() CASCADE;
DROP EXTENSION IF EXISTS citext;
