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
