-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm varchar(32);
GO

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD device_public_keys varchar(MAX);
GO

ALTER TABLE pa_activation ADD server_private_keys varchar(MAX);
GO

ALTER TABLE pa_activation ADD server_private_keys_encryption int CONSTRAINT DF_pa_activation_server_private_keys_encryption DEFAULT 0;
GO

ALTER TABLE pa_activation ADD server_public_keys varchar(MAX);
GO

ALTER TABLE pa_activation ADD shared_secret varchar(255);
GO

ALTER TABLE pa_activation ADD shared_secret_encryption int CONSTRAINT DF_pa_activation_shared_secret_encryption DEFAULT 0;
GO

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys varchar(MAX);
GO

ALTER TABLE pa_master_keypair ADD master_public_keys varchar(MAX);
GO

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 dynamic keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled bit CONSTRAINT DF_pa_activation_biometric_factor_enabled DEFAULT 0;
GO

ALTER TABLE pa_activation ADD biometric_factor_key varchar(255);
GO

ALTER TABLE pa_activation ADD biometric_factor_key_next varchar(255);
GO

ALTER TABLE pa_activation ADD knowledge_factor_key varchar(255);
GO

ALTER TABLE pa_activation ADD knowledge_factor_key_next varchar(255);
GO

