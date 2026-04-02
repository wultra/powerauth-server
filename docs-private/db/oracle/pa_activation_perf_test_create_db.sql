-- =============================================================================
-- PowerAuth pa_activation performance test — Create schema (user)
-- Oracle DB
--
-- Run as SYSDBA:
--   sqlplus sys/password@service AS SYSDBA @pa_activation_perf_test_create_db.sql
-- =============================================================================

-- Create dedicated tablespace
CREATE TABLESPACE pa_perf_test_ts
    DATAFILE 'pa_perf_test.dbf' SIZE 4G AUTOEXTEND ON NEXT 512M MAXSIZE UNLIMITED;

-- Create dedicated user/schema
CREATE USER pa_perf_test_user IDENTIFIED BY "pa_perf_test_password"
    DEFAULT TABLESPACE pa_perf_test_ts
    TEMPORARY TABLESPACE TEMP
    QUOTA UNLIMITED ON pa_perf_test_ts;

-- Grant privileges
GRANT CREATE SESSION TO pa_perf_test_user;
GRANT CREATE TABLE   TO pa_perf_test_user;
GRANT CREATE INDEX   TO pa_perf_test_user;
GRANT CREATE PROCEDURE TO pa_perf_test_user;

PROMPT
PROMPT Schema pa_perf_test_user created.
PROMPT
PROMPT Run the performance test with:
PROMPT   sqlplus pa_perf_test_user/pa_perf_test_password@service @pa_activation_perf_test.sql
PROMPT
PROMPT Drop the schema when done:
PROMPT   sqlplus sys/password@service AS SYSDBA @pa_activation_perf_test_drop_db.sql
