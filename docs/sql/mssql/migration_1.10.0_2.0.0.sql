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

ALTER TABLE pa_activation ADD server_private_keys_encryption int CONSTRAINT DF_pa_activation_server_private_keys_encryption DEFAULT 0 NOT NULL;
GO

ALTER TABLE pa_activation ADD server_public_keys varchar(MAX);
GO

ALTER TABLE pa_activation ADD shared_secret varchar(255);
GO

ALTER TABLE pa_activation ADD shared_secret_encryption int CONSTRAINT DF_pa_activation_shared_secret_encryption DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys varchar(MAX);
GO

ALTER TABLE pa_master_keypair ADD master_private_keys_encryption int CONSTRAINT DF_pa_master_keypair_master_private_keys_encryption DEFAULT 0 NOT NULL;
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

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::1::Roman Strobl
-- Add columns for crypto4 shared secret storage to pa_temporary_key table
ALTER TABLE pa_temporary_key ADD secret_key_base64 varchar(255);
GO

ALTER TABLE pa_temporary_key ADD secret_key_encryption int CONSTRAINT DF_pa_temporary_key_secret_key_encryption DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::2::Roman Strobl
-- Change the temporary keypair columns to nullable in pa_temporary_key table
ALTER TABLE pa_temporary_key ALTER COLUMN private_key_base64 varchar(255) NULL;
GO

ALTER TABLE pa_temporary_key ALTER COLUMN public_key_base64 varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250709-crypto4-activation-confirmation.xml::1::Roman Strobl
-- Add column confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD confirmation_pending bit CONSTRAINT DF_pa_activation_confirmation_pending DEFAULT 0;
GO

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::1::Roman Strobl
-- Add column upgrade_confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD upgrade_confirmation_pending bit CONSTRAINT DF_pa_upgrade_confirmation_pending DEFAULT 0;
GO

ALTER TABLE pa_activation ADD ctr_data_v4 varchar(255);
GO

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::1::Lubos Racansky
-- Add column parent_activation_id to pa_activation table
ALTER TABLE pa_activation ADD parent_activation_id varchar(37);
GO

ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_parent_activation_id_fk FOREIGN KEY (parent_activation_id) REFERENCES pa_activation (activation_id);
GO

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::2::Lubos Racansky
-- Add column transfer_type to pa_activation table
ALTER TABLE pa_activation ADD transfer_type varchar(32);
GO
