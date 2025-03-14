-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm VARCHAR(32);

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD device_public_keys TEXT;

ALTER TABLE pa_activation ADD server_private_keys TEXT;

ALTER TABLE pa_activation ADD server_private_keys_encryption INTEGER DEFAULT 0;

ALTER TABLE pa_activation ADD server_public_keys TEXT;

ALTER TABLE pa_activation ADD shared_secret TEXT;

ALTER TABLE pa_activation ADD shared_secret_encryption INTEGER DEFAULT 0;

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys TEXT;

ALTER TABLE pa_master_keypair ADD master_public_keys TEXT;

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled BOOLEAN DEFAULT FALSE;

ALTER TABLE pa_activation ADD biometric_factor_key VARCHAR(255);

ALTER TABLE pa_activation ADD biometric_factor_key_next VARCHAR(255);

ALTER TABLE pa_activation ADD knowledge_factor_key VARCHAR(255);

ALTER TABLE pa_activation ADD knowledge_factor_key_next VARCHAR(255);