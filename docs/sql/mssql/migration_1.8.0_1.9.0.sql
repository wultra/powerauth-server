-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::1::Petr Dvorak
-- Create a new table pa_temporary_key
CREATE TABLE pa_temporary_key (id varchar(37) NOT NULL, application_key varchar(32) NOT NULL, activation_id varchar(37), private_key_encryption int CONSTRAINT DF_pa_temporary_key_private_key_encryption DEFAULT 0 NOT NULL, private_key_base64 varchar(255) NOT NULL, public_key_base64 varchar(255) NOT NULL, timestamp_expires datetime2 NOT NULL, CONSTRAINT PK_PA_TEMPORARY_KEY PRIMARY KEY (id), CONSTRAINT pa_temporary_key_application_key_fk FOREIGN KEY (application_key) REFERENCES pa_application_version(application_key), CONSTRAINT pa_temporary_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::2::Petr Dvorak
-- Create a new index on pa_temporary_key(timestamp_expires)
CREATE NONCLUSTERED INDEX pa_temporary_key_ts_key_idx ON pa_temporary_key(timestamp_expires);
GO

-- Changeset powerauth-java-server/1.9.x/20240723-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_config table.
ALTER TABLE pa_application_config ADD encryption_mode varchar(255) CONSTRAINT DF_pa_application_config_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL;
GO

-- Changeset powerauth-java-server/1.9.x/20240906-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD encryption_mode varchar(255) CONSTRAINT DF_pa_application_callback_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL;
GO

-- Changeset powerauth-java-server/1.9.x/20240910-commit-phase.xml::1::Roman Strobl
-- Add commit_phase column to pa_activation table.
ALTER TABLE pa_activation ADD commit_phase int CONSTRAINT DF_pa_activation_commit_phase DEFAULT 0;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_callback_event
CREATE TABLE pa_application_callback_event (id varchar(36) NOT NULL, application_callback_id varchar(37) NOT NULL, callback_data varchar (max) NOT NULL, status varchar(32) NOT NULL, timestamp_created datetime2(6) CONSTRAINT DF_pa_application_callback_event_timestamp_created DEFAULT GETDATE(), timestamp_last_call datetime2(6), timestamp_next_call datetime2(6), timestamp_delete_after datetime2(6), attempts int CONSTRAINT DF_pa_application_callback_event_attempts DEFAULT 0, CONSTRAINT PK_PA_APPLICATION_CALLBACK_EVENT PRIMARY KEY (id), CONSTRAINT pa_application_callback_id_fk FOREIGN KEY (application_callback_id) REFERENCES pa_application_callback(id));
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts int;
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff int;
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period varchar(64);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE NONCLUSTERED INDEX pa_application_callback_event_status_idx ON pa_application_callback_event(status);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE NONCLUSTERED INDEX pa_application_callback_event_timestamp_delete_after_idx ON pa_application_callback_event(timestamp_delete_after);
GO
