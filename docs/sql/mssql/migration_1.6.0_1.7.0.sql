-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id varchar(255);
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol varchar(32) CONSTRAINT DF_pa_activation_protocol DEFAULT 'powerauth';
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation ALTER COLUMN extras varchar (max);
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id int NOT NULL, application_id int NOT NULL, [key] varchar(255) NOT NULL, [values] varchar (max), CONSTRAINT PK_PA_APPLICATION_CONFIG PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(key)
CREATE NONCLUSTERED INDEX pa_app_config_key_idx ON pa_application_config([key]);
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE pa_app_conf_seq START WITH 1 INCREMENT BY 1;
GO