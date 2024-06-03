-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id varchar(255);
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol varchar(32) CONSTRAINT DF_pa_activation_protocol DEFAULT 'powerauth';
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation ALTER COLUMN extras varchar (4000);
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::4::Lubos Racansky
ALTER TABLE pa_activation DROP CONSTRAINT DF_pa_activation_protocol;
GO

ALTER TABLE pa_activation
    ADD CONSTRAINT DF_pa_activation_protocol
    DEFAULT 'powerauth' FOR protocol;
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id int NOT NULL, application_id int NOT NULL, config_key varchar(255) NOT NULL, config_values varchar (max), CONSTRAINT PK_PA_APPLICATION_CONFIG PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE NONCLUSTERED INDEX pa_app_config_key_idx ON pa_application_config([config_key]);
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE pa_app_conf_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.7.x/20240312-fido2-authenticator.xml::1::Jan Pesek
-- Create a new table pa_fido2_authenticator
CREATE TABLE pa_fido2_authenticator (aaguid varchar(255) NOT NULL, description varchar(255) NOT NULL, signature_type varchar(255) NOT NULL, CONSTRAINT PK_PA_FIDO2_AUTHENTICATOR PRIMARY KEY (aaguid));
GO

-- Changeset powerauth-java-server/1.7.x/20240222-add-tag-1.7.0.xml::1::Lubos Racansky
