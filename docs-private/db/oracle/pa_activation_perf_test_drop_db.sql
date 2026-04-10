-- =============================================================================
-- PowerAuth pa_activation performance test — Drop schema (user)
-- Oracle DB
--
-- Run as SYSDBA:
--   sqlplus sys/password@localhost:1521/FREE AS SYSDBA @pa_activation_perf_test_drop_db.sql
-- =============================================================================

ALTER SESSION SET CONTAINER = FREEPDB1;

DROP USER pa_perf_test_user CASCADE;
DROP TABLESPACE pa_perf_test_ts INCLUDING CONTENTS AND DATAFILES;

PROMPT Schema pa_perf_test_user and tablespace pa_perf_test_ts dropped.
