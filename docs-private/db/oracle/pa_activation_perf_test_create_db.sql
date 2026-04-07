-- =============================================================================
-- PowerAuth pa_activation performance test — Create schema (user)
-- Oracle DB
--
-- IMPORTANT: Run against a PDB (pluggable database), NOT the CDB root.
-- ORA-65096 is raised when CREATE USER is run in CDB root without a C## prefix.
-- Connect as SYSDBA to the CDB and the script will switch to the PDB automatically:
--
--   sqlplus sys/password@localhost:1521/FREE AS SYSDBA @pa_activation_perf_test_create_db.sql
--   (Oracle 23ai Free: service=FREE, PDB=FREEPDB1)
--
--   sqlplus sys/password@localhost:1521/ORCLPDB1 AS SYSDBA @pa_activation_perf_test_create_db.sql
--   (Oracle 19c Enterprise: service=ORCLPDB1)
-- =============================================================================

-- Switch to PDB context (adjust PDB name if needed)
-- For Oracle 23ai Free use FREEPDB1; for Oracle 19c Enterprise use ORCLPDB1
ALTER SESSION SET CONTAINER = FREEPDB1;

-- Create dedicated tablespace
CREATE TABLESPACE pa_perf_test_ts
    DATAFILE 'pa_perf_test.dbf' SIZE 4G AUTOEXTEND ON NEXT 512M MAXSIZE UNLIMITED;

-- Create dedicated user/schema
CREATE USER pa_perf_test_user IDENTIFIED BY "pa_perf_test_password"
    DEFAULT TABLESPACE pa_perf_test_ts
    TEMPORARY TABLESPACE TEMP
    QUOTA UNLIMITED ON pa_perf_test_ts;

-- Grant privileges
GRANT CREATE SESSION   TO pa_perf_test_user;
GRANT CREATE TABLE     TO pa_perf_test_user;
GRANT CREATE PROCEDURE TO pa_perf_test_user;

PROMPT
PROMPT Schema pa_perf_test_user created.
PROMPT
PROMPT Run the performance test with:
PROMPT   sqlplus pa_perf_test_user/pa_perf_test_password@localhost:1521/ORCLPDB1 @pa_activation_perf_test.sql
PROMPT
PROMPT Drop the schema when done:
PROMPT   sqlplus sys/password@localhost:1521/ORCLPDB1 AS SYSDBA @pa_activation_perf_test_drop_db.sql
