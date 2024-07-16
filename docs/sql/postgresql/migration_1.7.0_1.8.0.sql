-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp;

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);

-- Changeset powerauth-java-server/1.8.x/20240517-fido2-authenticator-transports.xml::1::Jan Pesek
-- Add transports column in pa_fido2_authenticator table.
ALTER TABLE pa_fido2_authenticator ADD transports VARCHAR(255);

-- Changeset powerauth-java-server/1.8.x/20240529-add-status-reason.xml::1::Lubos Racansky
-- Add status_reason column to pa_operation table.
ALTER TABLE pa_operation ADD status_reason VARCHAR(32);

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_callback_event
CREATE TABLE pa_application_callback_event (id VARCHAR(36) NOT NULL, application_callback_id VARCHAR(37) NOT NULL, callback_data TEXT NOT NULL, status VARCHAR(32) NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE DEFAULT NOW(), timestamp_last_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_next_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_delete_after TIMESTAMP(6) WITHOUT TIME ZONE, attempts INTEGER DEFAULT 0, CONSTRAINT pa_application_callback_event_pkey PRIMARY KEY (id), CONSTRAINT pa_application_callback_id_fk FOREIGN KEY (application_callback_id) REFERENCES pa_application_callback(id));

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts INTEGER;

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff INTEGER;

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period VARCHAR(64);

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status, timestamp_next_call).
CREATE INDEX pa_application_callback_event_status_timestamp_next_call_idx ON pa_application_callback_event(status, timestamp_next_call);

-- Changeset powerauth-java-server/1.8.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE INDEX pa_application_callback_event_timestamp_delete_after_idx ON pa_application_callback_event(timestamp_delete_after);

