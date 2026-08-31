-- Production workflow retrieval and fenced transactional-outbox delivery.
-- This upgrades 001_scan_workflows.sql in place; it intentionally does not
-- duplicate or rewrite the aggregate/event schema established there.

BEGIN;

CREATE OR REPLACE FUNCTION enforce_scan_workflow_content_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD.sample_sha256 IS NOT NULL AND NEW.sample_sha256 IS DISTINCT FROM OLD.sample_sha256)
       OR (OLD.object_key IS NOT NULL AND NEW.object_key IS DISTINCT FROM OLD.object_key)
       OR (
           OLD.object_generation IS NOT NULL
           AND NEW.object_generation IS DISTINCT FROM OLD.object_generation
       ) THEN
        RAISE EXCEPTION 'sealed scan workflow content identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER scan_workflows_enforce_content_identity
BEFORE UPDATE ON scan_workflows
FOR EACH ROW EXECUTE FUNCTION enforce_scan_workflow_content_identity_update();

ALTER TABLE scan_workflow_outbox
    ADD COLUMN delivery_fencing_token bigint NOT NULL DEFAULT 0,
    ADD COLUMN failed_at timestamptz,
    ADD CONSTRAINT scan_workflow_outbox_delivery_fence_nonnegative
        CHECK (delivery_fencing_token >= 0),
    ADD CONSTRAINT scan_workflow_outbox_last_error_bounded
        CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
    ADD CONSTRAINT scan_workflow_outbox_terminal_delivery
        CHECK (NOT (published_at IS NOT NULL AND failed_at IS NOT NULL)),
    ADD CONSTRAINT scan_workflow_outbox_failed_metadata
        CHECK (failed_at IS NULL OR (published_at IS NULL AND last_error IS NOT NULL)),
    ADD CONSTRAINT scan_workflow_outbox_no_hostile_content
        CHECK (
            NOT payload ?| ARRAY[
                'binary', 'binary_data', 'content_bytes', 'extracted_strings',
                'file_bytes', 'file_content', 'raw_bytes', 'raw_file',
                'string_table', 'string_values', 'strings'
            ]
        );

ALTER TABLE scan_workflow_events
    ADD CONSTRAINT scan_workflow_events_no_hostile_content
        CHECK (
            NOT payload ?| ARRAY[
                'binary', 'binary_data', 'content_bytes', 'extracted_strings',
                'file_bytes', 'file_content', 'raw_bytes', 'raw_file',
                'string_table', 'string_values', 'strings'
            ]
        );

DROP INDEX scan_workflow_outbox_pending_idx;

CREATE INDEX scan_workflow_outbox_pending_idx
    ON scan_workflow_outbox (available_at, created_at, intent_id)
    WHERE published_at IS NULL AND failed_at IS NULL;

CREATE INDEX scan_workflow_outbox_active_lease_idx
    ON scan_workflow_outbox (locked_until, intent_id)
    WHERE published_at IS NULL AND failed_at IS NULL AND locked_until IS NOT NULL;

CREATE INDEX scan_workflows_tenant_history_idx
    ON scan_workflows (tenant_id, created_at DESC, scan_id DESC);

COMMIT;
