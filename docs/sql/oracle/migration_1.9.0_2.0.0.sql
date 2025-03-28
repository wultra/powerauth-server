-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm VARCHAR2(32);

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD device_public_keys CLOB;

ALTER TABLE pa_activation ADD server_private_keys CLOB;

ALTER TABLE pa_activation ADD server_private_keys_encryption INTEGER DEFAULT '0' NOT NULL;

ALTER TABLE pa_activation ADD server_public_keys CLOB;

ALTER TABLE pa_activation ADD shared_secret VARCHAR2(255);

ALTER TABLE pa_activation ADD shared_secret_encryption INTEGER DEFAULT '0' NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys CLOB;

ALTER TABLE pa_master_keypair ADD master_private_keys_encryption INTEGER DEFAULT '0' NOT NULL;

ALTER TABLE pa_master_keypair ADD master_public_keys CLOB;

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 dynamic keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled BOOLEAN DEFAULT 0;

ALTER TABLE pa_activation ADD biometric_factor_key VARCHAR2(255);

ALTER TABLE pa_activation ADD biometric_factor_key_next VARCHAR2(255);

ALTER TABLE pa_activation ADD knowledge_factor_key VARCHAR2(255);

ALTER TABLE pa_activation ADD knowledge_factor_key_next VARCHAR2(255);

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::1::Roman Strobl
-- Add columns for crypto4 shared secret storage to pa_temporary_key table
ALTER TABLE pa_temporary_key ADD secret_key_base64 VARCHAR2(255);

ALTER TABLE pa_temporary_key ADD secret_key_encryption INTEGER DEFAULT '0' NOT NULL;
