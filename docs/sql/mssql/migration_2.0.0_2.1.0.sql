-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.1.x/db.changelog-version.xml
-- Ran at: 28.04.26 15:48
-- Against: null@offline:mssql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-fix-nulls.xml::1::Vit Kotacka
-- Retrofit NULL activation_code values with unique LEGACY- prefixed placeholders
--             before adding the NOT NULL constraint. Skipped automatically (MARK_RAN) if no
--             NULL values are present, which is the expected case for all non-legacy databases.
--             Rollback is not supported — original NULL values cannot be restored.
UPDATE pa_activation
            SET activation_code = 'LEGACY-' + LOWER(CONVERT(varchar(36), NEWID()))
            WHERE activation_code IS NULL;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::0::Vit Kotacka
-- Drop non-unique index pa_activation_code before modifying the column. Required on MSSQL which blocks ALTER COLUMN when a dependent index exists. On environments where id=1..3 already ran successfully, this is a no-op (MARK_RAN).
DROP INDEX pa_activation_code ON pa_activation;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Add NOT NULL constraint on pa_activation(activation_code) to align the DB schema with the JPA entity definition. Applied before the unique constraint to fail fast if NULL values exist, avoiding an expensive index build on dirty data.
ALTER TABLE pa_activation ALTER COLUMN activation_code varchar(255) NOT NULL;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (activation_code, application_id) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check. activation_code is NOT NULL (see changeset id=1), so multiple NULLs bypassing the unique constraint is not a concern.
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (activation_code, application_id);
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::3::Vit Kotacka
-- Safety-net drop of non-unique index pa_activation_code. Normally already dropped by id=0; this changeset is a no-op (MARK_RAN) on fresh installs but ensures correctness on environments that ran id=1..3 before id=0 was introduced.
DROP INDEX pa_activation_code ON pa_activation;
GO

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::1::Pavel Sindelar
-- Add subject_id column to audit_log table
ALTER TABLE audit_log ADD subject_id varchar(256);
GO

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::2::Pavel Sindelar
-- Create a new index on audit_log(subject_id)
CREATE NONCLUSTERED INDEX audit_log_subject_id_idx ON audit_log(subject_id);
GO

