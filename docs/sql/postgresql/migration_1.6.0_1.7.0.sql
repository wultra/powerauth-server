-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id VARCHAR(255);

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol VARCHAR(32) DEFAULT 'powerauth';

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation ALTER COLUMN extras TYPE VARCHAR(4000) USING (extras::VARCHAR(4000));

-- Changeset powerauth-java-server/1.7.x/20240530-protocol-not-null.xml::5::Lubos Racansky
-- Make column pa_activation.protocol not-null.
ALTER TABLE pa_activation ALTER COLUMN  protocol SET NOT NULL;

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, config_key VARCHAR(255) NOT NULL, config_values TEXT, CONSTRAINT pa_application_config_pkey PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE INDEX pa_app_config_key_idx ON pa_application_config(config_key);

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE  IF NOT EXISTS pa_app_conf_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.7.x/20240312-fido2-authenticator.xml::1::Jan Pesek
-- Create a new table pa_fido2_authenticator
CREATE TABLE pa_fido2_authenticator (aaguid VARCHAR(255) NOT NULL, description VARCHAR(255) NOT NULL, signature_type VARCHAR(255) NOT NULL, CONSTRAINT pa_fido2_authenticator_pkey PRIMARY KEY (aaguid));

-- Changeset powerauth-java-server/1.7.x/20240222-add-tag-1.7.0.xml::1::Lubos Racansky
