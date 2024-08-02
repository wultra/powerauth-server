-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_callback_event
CREATE TABLE pa_application_callback_event (id VARCHAR(36) NOT NULL, application_callback_id VARCHAR(37) NOT NULL, callback_data TEXT NOT NULL, status VARCHAR(32) NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE DEFAULT NOW(), timestamp_last_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_next_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_delete_after TIMESTAMP(6) WITHOUT TIME ZONE, attempts INTEGER DEFAULT 0, CONSTRAINT pa_application_callback_event_pkey PRIMARY KEY (id), CONSTRAINT pa_application_callback_id_fk FOREIGN KEY (application_callback_id) REFERENCES pa_application_callback(id));

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts INTEGER;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff INTEGER;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period VARCHAR(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE INDEX pa_application_callback_event_status_idx ON pa_application_callback_event(status);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE INDEX pa_application_callback_event_timestamp_delete_after_idx ON pa_application_callback_event(timestamp_delete_after);

