-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp;

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);

