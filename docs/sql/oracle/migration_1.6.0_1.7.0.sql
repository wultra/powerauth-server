-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id VARCHAR2(255);

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol VARCHAR2(32) DEFAULT 'powerauth';

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation MODIFY extras CLOB;

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, config_key VARCHAR2(255) NOT NULL, config_values CLOB, CONSTRAINT PK_PA_APPLICATION_CONFIG PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE INDEX pa_app_config_key_idx ON pa_application_config(config_key);

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE pa_app_conf_seq START WITH 1 INCREMENT BY 1 CACHE 20;
