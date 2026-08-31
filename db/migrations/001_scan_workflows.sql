-- Durable hostile-content workflow, audit-event, and transactional-outbox schema.
-- PostgreSQL 15+. Application code must mutate the aggregate, append its event,
-- and append any outbox intent in one database transaction.

CREATE TYPE scan_workflow_state AS ENUM (
    'AWAITING_UPLOAD',
    'UPLOAD_RECEIVED',
    'VALIDATING',
    'QUEUED',
    'EXTRACTING',
    'VALIDATING_FEATURES',
    'SCORING',
    'APPLYING_POLICY',
    'PUBLISHING',
    'COMPLETE',
    'REJECTED',
    'INCONCLUSIVE',
    'FAILED',
    'CANCELLED',
    'EXPIRED'
);

CREATE TABLE scan_workflow_transitions (
    from_state scan_workflow_state NOT NULL,
    to_state scan_workflow_state NOT NULL,
    PRIMARY KEY (from_state, to_state),
    CHECK (from_state <> to_state)
);

INSERT INTO scan_workflow_transitions (from_state, to_state) VALUES
    ('AWAITING_UPLOAD', 'UPLOAD_RECEIVED'),
    ('UPLOAD_RECEIVED', 'VALIDATING'),
    ('VALIDATING', 'QUEUED'),
    ('QUEUED', 'EXTRACTING'),
    ('EXTRACTING', 'VALIDATING_FEATURES'),
    ('VALIDATING_FEATURES', 'SCORING'),
    ('SCORING', 'APPLYING_POLICY'),
    ('APPLYING_POLICY', 'PUBLISHING'),
    ('PUBLISHING', 'COMPLETE'),
    ('AWAITING_UPLOAD', 'REJECTED'),
    ('UPLOAD_RECEIVED', 'REJECTED'),
    ('VALIDATING', 'REJECTED'),
    ('VALIDATING', 'INCONCLUSIVE'),
    ('QUEUED', 'INCONCLUSIVE'),
    ('EXTRACTING', 'INCONCLUSIVE'),
    ('VALIDATING_FEATURES', 'INCONCLUSIVE'),
    ('SCORING', 'INCONCLUSIVE'),
    ('APPLYING_POLICY', 'INCONCLUSIVE'),
    ('PUBLISHING', 'INCONCLUSIVE'),
    ('AWAITING_UPLOAD', 'FAILED'),
    ('UPLOAD_RECEIVED', 'FAILED'),
    ('VALIDATING', 'FAILED'),
    ('QUEUED', 'FAILED'),
    ('EXTRACTING', 'FAILED'),
    ('VALIDATING_FEATURES', 'FAILED'),
    ('SCORING', 'FAILED'),
    ('APPLYING_POLICY', 'FAILED'),
    ('PUBLISHING', 'FAILED'),
    ('AWAITING_UPLOAD', 'CANCELLED'),
    ('UPLOAD_RECEIVED', 'CANCELLED'),
    ('VALIDATING', 'CANCELLED'),
    ('QUEUED', 'CANCELLED'),
    ('EXTRACTING', 'CANCELLED'),
    ('VALIDATING_FEATURES', 'CANCELLED'),
    ('SCORING', 'CANCELLED'),
    ('APPLYING_POLICY', 'CANCELLED'),
    ('PUBLISHING', 'CANCELLED'),
    ('AWAITING_UPLOAD', 'EXPIRED'),
    ('UPLOAD_RECEIVED', 'EXPIRED'),
    ('VALIDATING', 'EXPIRED'),
    ('QUEUED', 'EXPIRED'),
    ('EXTRACTING', 'EXPIRED'),
    ('VALIDATING_FEATURES', 'EXPIRED'),
    ('SCORING', 'EXPIRED'),
    ('APPLYING_POLICY', 'EXPIRED'),
    ('PUBLISHING', 'EXPIRED');

CREATE TABLE scan_workflows (
    tenant_id text NOT NULL CHECK (length(btrim(tenant_id)) BETWEEN 1 AND 255),
    scan_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (length(btrim(idempotency_key)) BETWEEN 1 AND 255),
    state scan_workflow_state NOT NULL DEFAULT 'AWAITING_UPLOAD',
    sample_sha256 char(64),
    object_key text,
    object_generation text,
    analysis_release_id text NOT NULL,
    policy_snapshot_id text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    state_changed_at timestamptz NOT NULL,
    expires_at timestamptz,
    terminal_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner text,
    lease_expires_at timestamptz,
    fencing_token bigint NOT NULL DEFAULT 0 CHECK (fencing_token >= 0),
    failure_reason text,
    result_object_key text,
    result_sha256 char(64),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    PRIMARY KEY (tenant_id, scan_id),
    UNIQUE (tenant_id, idempotency_key),
    CHECK (length(btrim(analysis_release_id)) BETWEEN 1 AND 255),
    CHECK (length(btrim(policy_snapshot_id)) BETWEEN 1 AND 255),
    CHECK (sample_sha256 IS NULL OR sample_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (result_sha256 IS NULL OR result_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK ((sample_sha256 IS NULL) = (object_generation IS NULL)),
    CHECK (sample_sha256 IS NULL OR object_key IS NOT NULL),
    CHECK (object_key IS NULL OR length(btrim(object_key)) > 0),
    CHECK (object_generation IS NULL OR length(btrim(object_generation)) > 0),
    CHECK (result_object_key IS NULL OR length(btrim(result_object_key)) > 0),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (lease_owner IS NULL OR length(btrim(lease_owner)) > 0),
    CHECK (updated_at >= created_at AND state_changed_at >= created_at),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (
        state NOT IN (
            'UPLOAD_RECEIVED', 'VALIDATING', 'QUEUED', 'EXTRACTING',
            'VALIDATING_FEATURES', 'SCORING', 'APPLYING_POLICY', 'PUBLISHING', 'COMPLETE'
        )
        OR (sample_sha256 IS NOT NULL AND object_key IS NOT NULL AND object_generation IS NOT NULL)
    ),
    CHECK (
        (state = 'COMPLETE'
            AND terminal_at IS NOT NULL
            AND failure_reason IS NULL
            AND result_object_key IS NOT NULL
            AND result_sha256 IS NOT NULL
            AND lease_owner IS NULL)
        OR
        (state IN ('REJECTED', 'INCONCLUSIVE', 'FAILED', 'CANCELLED', 'EXPIRED')
            AND terminal_at IS NOT NULL
            AND failure_reason IS NOT NULL
            AND length(btrim(failure_reason)) > 0
            AND result_object_key IS NULL
            AND result_sha256 IS NULL
            AND lease_owner IS NULL)
        OR
        (state NOT IN ('COMPLETE', 'REJECTED', 'INCONCLUSIVE', 'FAILED', 'CANCELLED', 'EXPIRED')
            AND terminal_at IS NULL
            AND failure_reason IS NULL
            AND result_object_key IS NULL
            AND result_sha256 IS NULL)
    )
);

CREATE UNIQUE INDEX scan_workflows_analysis_identity_uq
    ON scan_workflows (tenant_id, sample_sha256, object_generation, analysis_release_id)
    WHERE sample_sha256 IS NOT NULL;

CREATE INDEX scan_workflows_state_lease_idx
    ON scan_workflows (state, lease_expires_at, created_at)
    WHERE state NOT IN ('COMPLETE', 'REJECTED', 'INCONCLUSIVE', 'FAILED', 'CANCELLED', 'EXPIRED');

CREATE OR REPLACE FUNCTION enforce_scan_workflow_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state IN ('COMPLETE', 'REJECTED', 'INCONCLUSIVE', 'FAILED', 'CANCELLED', 'EXPIRED')
       AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal scan workflow %/% is immutable', OLD.tenant_id, OLD.scan_id;
    END IF;

    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'scan workflow version must advance exactly once';
    END IF;

    IF NEW.state <> OLD.state AND NOT EXISTS (
        SELECT 1
        FROM scan_workflow_transitions transition
        WHERE transition.from_state = OLD.state AND transition.to_state = NEW.state
    ) THEN
        RAISE EXCEPTION 'illegal scan workflow transition from % to %', OLD.state, NEW.state;
    END IF;

    IF NEW.tenant_id <> OLD.tenant_id
       OR NEW.scan_id <> OLD.scan_id
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.analysis_release_id <> OLD.analysis_release_id
       OR NEW.policy_snapshot_id <> OLD.policy_snapshot_id
       OR NEW.created_at <> OLD.created_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'immutable scan workflow identity cannot be changed';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER scan_workflows_enforce_update
BEFORE UPDATE ON scan_workflows
FOR EACH ROW EXECUTE FUNCTION enforce_scan_workflow_update();

CREATE TABLE scan_workflow_events (
    event_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    scan_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 0),
    event_type text NOT NULL CHECK (length(btrim(event_type)) BETWEEN 1 AND 255),
    from_state scan_workflow_state,
    to_state scan_workflow_state NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
    UNIQUE (tenant_id, scan_id, sequence),
    FOREIGN KEY (tenant_id, scan_id)
        REFERENCES scan_workflows (tenant_id, scan_id) ON DELETE RESTRICT,
    CHECK (
        (sequence = 0 AND from_state IS NULL)
        OR (sequence > 0 AND from_state IS NOT NULL)
    )
);

CREATE INDEX scan_workflow_events_timeline_idx
    ON scan_workflow_events (tenant_id, scan_id, occurred_at, sequence);

CREATE TABLE scan_workflow_outbox (
    intent_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    scan_id uuid NOT NULL,
    workflow_version bigint NOT NULL CHECK (workflow_version >= 0),
    topic text NOT NULL CHECK (length(btrim(topic)) BETWEEN 1 AND 255),
    deduplication_key text NOT NULL CHECK (length(btrim(deduplication_key)) BETWEEN 1 AND 255),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL,
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    locked_by text,
    locked_until timestamptz,
    last_error text,
    UNIQUE (tenant_id, deduplication_key),
    FOREIGN KEY (tenant_id, scan_id)
        REFERENCES scan_workflows (tenant_id, scan_id) ON DELETE RESTRICT,
    CHECK ((locked_by IS NULL) = (locked_until IS NULL))
);

CREATE INDEX scan_workflow_outbox_pending_idx
    ON scan_workflow_outbox (available_at, created_at)
    WHERE published_at IS NULL;
