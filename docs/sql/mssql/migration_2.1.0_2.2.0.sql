-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.2.x/db.changelog-version.xml
-- Ran at: 7/8/26, 11:27 PM
-- Against: null@offline:mssql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store the signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm varchar(32);
GO

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format varchar(32);
GO

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Add signature_asymmetric CLOB column to pa_signature_audit table to store asymmetric signatures (ECDSA, ML-DSA)
ALTER TABLE pa_signature_audit ADD signature_asymmetric varchar(MAX);
GO

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::4::Roman Strobl
-- Make signature column nullable in pa_signature_audit table because asymmetric audit records store their value in signature_asymmetric and leave signature null
ALTER TABLE pa_signature_audit ALTER COLUMN signature varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire datetime2(6);
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count bigint CONSTRAINT DF_pa_activation_temporary_block_count DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::3::Roman Strobl
-- Create a partial index on pa_activation(timestamp_block_expire) to support the scheduled expiration of temporary activation blocks (on Oracle a plain single-column index achieves the same effect, since all-null keys are not indexed)
CREATE NONCLUSTERED INDEX pa_activation_block_expire_idx ON pa_activation(timestamp_block_expire) WHERE timestamp_block_expire IS NOT NULL;
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::1::Roman Strobl
-- Create a new table pa_config_store
CREATE TABLE pa_config_store (id bigint NOT NULL, application_id int NOT NULL, activation_id varchar(37), config_scope varchar(32) NOT NULL, config_data varchar(MAX), encryption_mode varchar(255) CONSTRAINT DF_pa_config_store_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL, timestamp_created datetime2 NOT NULL, timestamp_last_updated datetime2, CONSTRAINT PK_PA_CONFIG_STORE PRIMARY KEY (id), CONSTRAINT pa_config_store_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT pa_config_store_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::2::Roman Strobl
-- Create a new sequence pa_config_store_seq
CREATE SEQUENCE pa_config_store_seq START WITH 1 INCREMENT BY 50 CACHE 20;
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::3::Roman Strobl
-- Create a new index on pa_config_store(application_id)
CREATE NONCLUSTERED INDEX pa_config_store_application_id_idx ON pa_config_store(application_id);
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::4::Roman Strobl
-- Create a new index on pa_config_store(activation_id)
CREATE NONCLUSTERED INDEX pa_config_store_activation_id_idx ON pa_config_store(activation_id);
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::5::Roman Strobl
-- Create a unique index on pa_config_store(application_id, activation_id, config_scope).
CREATE UNIQUE NONCLUSTERED INDEX pa_config_store_application_id_activation_id_config_scope_idx ON pa_config_store(application_id, activation_id, config_scope);
GO

