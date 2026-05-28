-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.2.x/db.changelog-version.xml
-- Ran at: 5/11/26, 12:46 PM
-- Against: null@offline:postgresql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Change data type of signature column in pa_signature_audit table from varchar(255) to varchar(8000) to support longer asymmetric signatures
ALTER TABLE pa_signature_audit ALTER COLUMN signature TYPE VARCHAR(8000) USING (signature::VARCHAR(8000));

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire TIMESTAMP(6) WITHOUT TIME ZONE;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count BIGINT DEFAULT 0 NOT NULL;
