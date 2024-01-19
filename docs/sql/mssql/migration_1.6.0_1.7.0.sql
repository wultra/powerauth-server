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
