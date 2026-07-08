-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.2.x/db.changelog-version.xml
-- Ran at: 07/07/2026, 21:11
-- Against: null@offline:postgresql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store the signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Add signature_asymmetric CLOB column to pa_signature_audit table to store asymmetric signatures (ECDSA, ML-DSA)
ALTER TABLE pa_signature_audit ADD signature_asymmetric TEXT;

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::4::Roman Strobl
-- Rename signature column to auth_code in pa_signature_audit table to match the authentication code terminology
ALTER TABLE pa_signature_audit RENAME COLUMN signature TO auth_code;

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::5::Roman Strobl
-- Make auth_code column nullable in pa_signature_audit table because asymmetric audit records store their value in signature_asymmetric and leave auth_code null
ALTER TABLE pa_signature_audit ALTER COLUMN  auth_code DROP NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire TIMESTAMP(6) WITHOUT TIME ZONE;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count BIGINT DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::3::Roman Strobl
-- Create a partial index on pa_activation(timestamp_block_expire) to support the scheduled expiration of temporary activation blocks (on Oracle a plain single-column index achieves the same effect, since all-null keys are not indexed)
CREATE INDEX pa_activation_block_expire_idx ON pa_activation(timestamp_block_expire) WHERE timestamp_block_expire IS NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::1::Roman Strobl
-- Create a new table pa_config_store
CREATE TABLE pa_config_store (id BIGINT NOT NULL, application_id INTEGER NOT NULL, activation_id VARCHAR(37), config_scope VARCHAR(32) NOT NULL, config_data TEXT, encryption_mode VARCHAR(255) DEFAULT 'NO_ENCRYPTION' NOT NULL, timestamp_created TIMESTAMP WITHOUT TIME ZONE NOT NULL, timestamp_last_updated TIMESTAMP WITHOUT TIME ZONE, CONSTRAINT pa_config_store_pkey PRIMARY KEY (id), CONSTRAINT pa_config_store_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id), CONSTRAINT pa_config_store_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::2::Roman Strobl
-- Create a new sequence pa_config_store_seq
CREATE SEQUENCE  IF NOT EXISTS pa_config_store_seq START WITH 1 INCREMENT BY 50 CACHE 20;

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::3::Roman Strobl
-- Create a new index on pa_config_store(application_id)
CREATE INDEX pa_config_store_application_id_idx ON pa_config_store(application_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::4::Roman Strobl
-- Create a new index on pa_config_store(activation_id)
CREATE INDEX pa_config_store_activation_id_idx ON pa_config_store(activation_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::5::Roman Strobl
-- Create a unique index on pa_config_store(application_id, activation_id, config_scope).
CREATE UNIQUE INDEX pa_config_store_application_id_activation_id_config_scope_idx ON pa_config_store(application_id, activation_id, config_scope);

