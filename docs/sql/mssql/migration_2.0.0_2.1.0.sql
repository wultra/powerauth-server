-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/2.1.x/db.changelog-version.xml
-- Ran at: 18.03.26 12:49
-- Against: null@offline:mssql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Drop non-unique index on pa_activation(activation_code) before replacing with unique constraint
DROP INDEX pa_activation_code ON pa_activation;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (application_id, activation_code) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (application_id, activation_code);
GO

