-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.1.x/db.changelog-version.xml
-- Ran at: 08.04.26 12:03
-- Against: null@offline:postgresql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-fix-nulls.xml::1::Vit Kotacka
-- Retrofit NULL activation_code values with unique LEGACY- prefixed placeholders
--             before adding the NOT NULL constraint. Skipped automatically (MARK_RAN) if no
--             NULL values are present, which is the expected case for all non-legacy databases.
--             Rollback is not supported — original NULL values cannot be restored.
UPDATE pa_activation
            SET activation_code = 'LEGACY-' || gen_random_uuid()::text
            WHERE activation_code IS NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Add NOT NULL constraint on pa_activation(activation_code) to align the DB schema with the JPA entity definition. Applied before the unique constraint to fail fast if NULL values exist, avoiding an expensive index build on dirty data.
ALTER TABLE pa_activation ALTER COLUMN  activation_code SET NOT NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (activation_code, application_id) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check. activation_code is NOT NULL (see changeset id=1), so multiple NULLs bypassing the unique constraint is not a concern.
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (activation_code, application_id);

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::3::Vit Kotacka
-- Drop non-unique index on pa_activation(activation_code) replaced by unique constraint pa_activation_code_application_uk
DROP INDEX pa_activation_code;

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::1::Pavel Sindelar
-- Add subject_id column to audit_log table
ALTER TABLE audit_log ADD subject_id VARCHAR(256);

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::2::Pavel Sindelar
-- Create a new index on audit_log(subject_id)
CREATE INDEX audit_log_subject_id_idx ON audit_log(subject_id);
