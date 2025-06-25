-- Changeset powerauth-java-server/1.10.x/20250609-activation-additional-data.xml::1::Lubos Racansky
-- Add additional_data column to pa_activation table.
ALTER TABLE pa_activation ADD additional_data TEXT;
