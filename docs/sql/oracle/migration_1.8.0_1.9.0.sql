-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::1::Petr Dvorak
-- Create a new table pa_temporary_key
CREATE TABLE pa_temporary_key (id VARCHAR2(37) NOT NULL, application_key VARCHAR2(32) NOT NULL, activation_id VARCHAR2(37), private_key_encryption INTEGER DEFAULT 0 NOT NULL, private_key_base64 VARCHAR2(255) NOT NULL, public_key_base64 VARCHAR2(255) NOT NULL, timestamp_expires TIMESTAMP NOT NULL, CONSTRAINT PK_PA_TEMPORARY_KEY PRIMARY KEY (id), CONSTRAINT pa_temporary_key_application_key_fk FOREIGN KEY (application_key) REFERENCES pa_application_version(application_key), CONSTRAINT pa_temporary_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::2::Petr Dvorak
-- Create a new index on pa_temporary_key(timestamp_expires)
CREATE INDEX pa_temporary_key_ts_key_idx ON pa_temporary_key(timestamp_expires);

-- Changeset powerauth-java-server/1.9.x/20240723-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_config table.
ALTER TABLE pa_application_config ADD encryption_mode VARCHAR2(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240906-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD encryption_mode VARCHAR2(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240910-commit-phase.xml::1::Roman Strobl
-- Add commit_phase column to pa_activation table.
ALTER TABLE pa_activation ADD commit_phase INTEGER DEFAULT '0';

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_callback_event
CREATE TABLE pa_application_callback_event (id NUMBER(38, 0) NOT NULL, application_callback_id VARCHAR2(37) NOT NULL, callback_data CLOB NOT NULL, status VARCHAR2(32) NOT NULL, timestamp_created TIMESTAMP(6) DEFAULT sysdate NOT NULL, timestamp_last_call TIMESTAMP(6), timestamp_next_call TIMESTAMP(6), timestamp_delete_after TIMESTAMP(6), timestamp_rerun_after TIMESTAMP(6), attempts INTEGER DEFAULT 0 NOT NULL, idempotency_key VARCHAR2(36) NOT NULL, CONSTRAINT PK_PA_APPLICATION_CALLBACK_EVE PRIMARY KEY (id), CONSTRAINT pa_application_callback_id_fk FOREIGN KEY (application_callback_id) REFERENCES pa_application_callback(id));

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts INTEGER;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff VARCHAR2(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period VARCHAR2(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE INDEX pa_app_cb_event_status_idx ON pa_application_callback_event(status);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE INDEX pa_app_cb_event_ts_del_idx ON pa_application_callback_event(timestamp_delete_after);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::7::Jan Pesek
-- Create a new sequence pa_app_callback_event_seq
CREATE SEQUENCE pa_app_callback_event_seq START WITH 1 INCREMENT BY 50 CACHE 20;
