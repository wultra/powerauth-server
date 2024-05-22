-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp ON pa_operation;
GO

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE NONCLUSTERED INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);
GO

-- Changeset powerauth-java-server/1.8.x/20240517-fido2-authenticator-transports.xml::1::Jan Pesek
-- Add transports column in pa_fido2_authenticator table.
ALTER TABLE pa_fido2_authenticator ADD transports varchar(255);
GO

