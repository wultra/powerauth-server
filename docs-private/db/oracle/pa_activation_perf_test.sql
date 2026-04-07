-- =============================================================================
-- PowerAuth pa_activation — Performance test: unique constraint on 10M rows
-- Oracle DB
--
-- Simulates the migration scenario:
--   1. Table with 10M rows and only a non-unique single-column index (pa_activation_code)
--   2. Step 1: Add NOT NULL on activation_code
--   3. Step 2: Add unique constraint (application_id, activation_code)
--   4. Step 3: Drop old non-unique index
--
-- Run with: sqlplus pa_perf_test_user/pa_perf_test_password@localhost:1521/ORCLPDB1 @pa_activation_perf_test.sql
-- Monitor index build progress in a separate session (see MONITORING section at the bottom).
--
-- Results are stored in pa_perf_test_results and can be queried after the run:
--   SELECT * FROM pa_perf_test_results ORDER BY step;
-- =============================================================================

SET SERVEROUTPUT ON SIZE UNLIMITED
SET TIMING ON
SET FEEDBACK OFF

PROMPT
PROMPT ============================================================
PROMPT  PowerAuth pa_activation constraint performance test
PROMPT ============================================================

-- -----------------------------------------------------------------------------
-- 1. SETUP: Drop existing tables, create results table and test table.
--    activation_code is intentionally NULLABLE to simulate the current state.
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [1/6] Creating test tables ---

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE pa_activation_perf_test';
EXCEPTION
    WHEN OTHERS THEN IF SQLCODE != -942 THEN RAISE; END IF;
END;
/

BEGIN
    EXECUTE IMMEDIATE 'DROP TABLE pa_perf_test_results';
EXCEPTION
    WHEN OTHERS THEN IF SQLCODE != -942 THEN RAISE; END IF;
END;
/

-- Results table — persists all measurements after the script finishes
CREATE TABLE pa_perf_test_results (
    step        NUMBER(3)                    NOT NULL,
    description VARCHAR2(255)                NOT NULL,
    started_at  TIMESTAMP                    NOT NULL,
    finished_at TIMESTAMP                    NOT NULL,
    duration    INTERVAL DAY(0) TO SECOND(6) NOT NULL
);

CREATE TABLE pa_activation_perf_test (
    activation_id               VARCHAR2(37)  NOT NULL,
    application_id              INTEGER       NOT NULL,
    user_id                     VARCHAR2(255) NOT NULL,
    activation_name             VARCHAR2(255),
    activation_code             VARCHAR2(255),              -- nullable (current state before migration)
    activation_status           INTEGER       NOT NULL,
    activation_otp              VARCHAR2(255),
    activation_otp_validation   INTEGER       DEFAULT 0  NOT NULL,
    blocked_reason              VARCHAR2(255),
    counter                     INTEGER       NOT NULL,
    ctr_data                    VARCHAR2(255),
    device_public_key_base64    VARCHAR2(255),
    extras                      VARCHAR2(255),
    platform                    VARCHAR2(255),
    device_info                 VARCHAR2(255),
    flags                       VARCHAR2(255),
    failed_attempts             INTEGER       NOT NULL,
    max_failed_attempts         INTEGER       DEFAULT 5  NOT NULL,
    server_private_key_base64   VARCHAR2(255) NOT NULL,
    server_private_key_encryption INTEGER     DEFAULT 0  NOT NULL,
    server_public_key_base64    VARCHAR2(255) NOT NULL,
    timestamp_activation_expire TIMESTAMP(6)  NOT NULL,
    timestamp_created           TIMESTAMP(6)  NOT NULL,
    timestamp_last_used         TIMESTAMP(6)  NOT NULL,
    timestamp_last_change       TIMESTAMP(6),
    master_keypair_id           INTEGER,
    version                     INTEGER       DEFAULT 2,
    CONSTRAINT pa_activation_perf_test_pk PRIMARY KEY (activation_id)
);

-- Simulate the existing non-unique single-column index (starting state before migration)
CREATE INDEX pa_activation_perf_test_code_old ON pa_activation_perf_test(activation_code);

-- -----------------------------------------------------------------------------
-- 2. DATA GENERATION: Insert 10,000,000 rows in batches of 100,000
--    activation_id:   UUID derived from SYS_GUID() (one call per row)
--    activation_code: XXXXX-XXXXX-XXXXX-XXXXX derived from row number (deterministic, unique)
--    application_id:  spread across 10 apps
--    Note: Batch inserts avoid undo/redo log pressure of a single 10M-row statement.
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [2/6] Inserting 10,000,000 rows in batches (this may take several minutes) ---

DECLARE
    v_start      TIMESTAMP := SYSTIMESTAMP;
    v_end        TIMESTAMP;
    v_batch_size CONSTANT PLS_INTEGER := 100000;
    v_total      CONSTANT PLS_INTEGER := 10000000;
    v_offset     PLS_INTEGER := 0;

    TYPE t_varchar37  IS TABLE OF VARCHAR2(37)  INDEX BY PLS_INTEGER;
    TYPE t_integer    IS TABLE OF INTEGER       INDEX BY PLS_INTEGER;
    TYPE t_varchar255 IS TABLE OF VARCHAR2(255) INDEX BY PLS_INTEGER;
    TYPE t_timestamp  IS TABLE OF TIMESTAMP(6)  INDEX BY PLS_INTEGER;

    t_act_id     t_varchar37;
    t_app_id     t_integer;
    t_user_id    t_varchar255;
    t_act_code   t_varchar255;
    t_act_status t_integer;
    t_srv_priv   t_varchar255;
    t_srv_pub    t_varchar255;
    t_ts_exp     t_timestamp;
    t_ts_cre     t_timestamp;
    t_ts_use     t_timestamp;

    v_now        TIMESTAMP := SYSTIMESTAMP;
    v_i          PLS_INTEGER;
BEGIN
    WHILE v_offset < v_total LOOP
        t_act_id.DELETE;  t_app_id.DELETE;  t_user_id.DELETE;
        t_act_code.DELETE; t_act_status.DELETE;
        t_srv_priv.DELETE; t_srv_pub.DELETE;
        t_ts_exp.DELETE;  t_ts_cre.DELETE;  t_ts_use.DELETE;

        FOR j IN 1 .. v_batch_size LOOP
            v_i := v_offset + j;
            EXIT WHEN v_i > v_total;

            t_act_id(j)     := REGEXP_REPLACE(LOWER(RAWTOHEX(SYS_GUID())),
                                   '([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})',
                                   '\1-\2-\3-\4-\5');
            t_app_id(j)     := MOD(v_i - 1, 10) + 1;
            t_user_id(j)    := 'user-' || TO_CHAR(MOD(v_i - 1, 1000000));
            t_act_code(j)   := SUBSTR(LPAD(TO_CHAR(v_i, 'FMXXXXXXXXXXXXXXXXXX'), 20, '0'),  1, 5) || '-' ||
                                SUBSTR(LPAD(TO_CHAR(v_i, 'FMXXXXXXXXXXXXXXXXXX'), 20, '0'),  6, 5) || '-' ||
                                SUBSTR(LPAD(TO_CHAR(v_i, 'FMXXXXXXXXXXXXXXXXXX'), 20, '0'), 11, 5) || '-' ||
                                SUBSTR(LPAD(TO_CHAR(v_i, 'FMXXXXXXXXXXXXXXXXXX'), 20, '0'), 16, 5);
            t_act_status(j) := CASE MOD(v_i, 10)
                                    WHEN 0 THEN 1 WHEN 1 THEN 1
                                    WHEN 2 THEN 3 WHEN 3 THEN 3 WHEN 4 THEN 3 WHEN 5 THEN 3 WHEN 6 THEN 3
                                    WHEN 7 THEN 4 WHEN 8 THEN 4
                                    ELSE 5
                                END;
            t_srv_priv(j)   := SUBSTR(RAWTOHEX(SYS_GUID()), 1, 44);
            t_srv_pub(j)    := SUBSTR(RAWTOHEX(SYS_GUID()), 1, 44);
            t_ts_exp(j)     := v_now + INTERVAL '5' MINUTE;
            t_ts_cre(j)     := v_now - NUMTODSINTERVAL(v_i, 'SECOND');
            t_ts_use(j)     := v_now - NUMTODSINTERVAL(v_i, 'SECOND');
        END LOOP;

        FORALL j IN INDICES OF t_act_id
            INSERT INTO pa_activation_perf_test (
                activation_id, application_id, user_id, activation_code,
                activation_status, activation_otp_validation, counter,
                failed_attempts, max_failed_attempts,
                server_private_key_base64, server_private_key_encryption,
                server_public_key_base64,
                timestamp_activation_expire, timestamp_created, timestamp_last_used
            ) VALUES (
                t_act_id(j), t_app_id(j), t_user_id(j), t_act_code(j),
                t_act_status(j), 0, 0, 0, 5,
                t_srv_priv(j), 0, t_srv_pub(j),
                t_ts_exp(j), t_ts_cre(j), t_ts_use(j)
            );

        COMMIT;
        v_offset := v_offset + v_batch_size;
    END LOOP;

    v_end := SYSTIMESTAMP;
    INSERT INTO pa_perf_test_results VALUES (0, 'Data generation (10M rows)', v_start, v_end, v_end - v_start);
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Data generation completed in: ' || TO_CHAR(v_end - v_start));
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('ERROR during data generation at offset ' || v_offset || ': ' || SQLERRM);
        ROLLBACK;
        RAISE;
END;
/

-- Quick sanity check
SELECT COUNT(*) AS total_rows FROM pa_activation_perf_test;

-- -----------------------------------------------------------------------------
-- 3. MEASURE STEP 1: Add NOT NULL constraint on activation_code
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [3/6] Step 1: Adding NOT NULL constraint on activation_code ---

DECLARE
    v_start TIMESTAMP := SYSTIMESTAMP;
    v_end   TIMESTAMP;
BEGIN
    EXECUTE IMMEDIATE 'ALTER TABLE pa_activation_perf_test MODIFY (activation_code VARCHAR2(255) NOT NULL)';
    v_end := SYSTIMESTAMP;
    INSERT INTO pa_perf_test_results VALUES (1, 'ADD NOT NULL on activation_code', v_start, v_end, v_end - v_start);
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('NOT NULL constraint added in: ' || TO_CHAR(v_end - v_start));
END;
/

-- -----------------------------------------------------------------------------
-- 4. MEASURE STEP 2: Add unique constraint on (application_id, activation_code)
--    This is the most expensive operation — builds a new B-tree index.
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [4/6] Step 2: Adding unique constraint (application_id, activation_code) ---
PROMPT          Monitor progress in another session — see MONITORING section at the bottom.

DECLARE
    v_start TIMESTAMP := SYSTIMESTAMP;
    v_end   TIMESTAMP;
BEGIN
    EXECUTE IMMEDIATE 'ALTER TABLE pa_activation_perf_test ADD CONSTRAINT pa_activation_perf_test_code_app_uk UNIQUE (application_id, activation_code)';
    v_end := SYSTIMESTAMP;
    INSERT INTO pa_perf_test_results VALUES (2, 'ADD UNIQUE (application_id, activation_code)', v_start, v_end, v_end - v_start);
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Unique constraint added in: ' || TO_CHAR(v_end - v_start));
END;
/

-- -----------------------------------------------------------------------------
-- 5. MEASURE STEP 3: Drop old non-unique index
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [5/6] Step 3: Dropping old non-unique index ---

DECLARE
    v_start TIMESTAMP := SYSTIMESTAMP;
    v_end   TIMESTAMP;
BEGIN
    EXECUTE IMMEDIATE 'DROP INDEX pa_activation_perf_test_code_old';
    v_end := SYSTIMESTAMP;
    INSERT INTO pa_perf_test_results VALUES (3, 'DROP old non-unique index', v_start, v_end, v_end - v_start);
    COMMIT;
    DBMS_OUTPUT.PUT_LINE('Old index dropped in: ' || TO_CHAR(v_end - v_start));
END;
/

-- -----------------------------------------------------------------------------
-- 6. VERIFY: Confirm the constraint and indexes are in place
-- -----------------------------------------------------------------------------
PROMPT
PROMPT --- [6/6] Verification ---

SELECT constraint_name, constraint_type, status
FROM user_constraints
WHERE table_name = 'PA_ACTIVATION_PERF_TEST'
ORDER BY constraint_type;

SELECT index_name, uniqueness, status
FROM user_indexes
WHERE table_name = 'PA_ACTIVATION_PERF_TEST'
ORDER BY index_name;

-- Final results summary
PROMPT
PROMPT --- Results summary (also persisted in pa_perf_test_results) ---

SELECT step, description, started_at, finished_at, duration
FROM pa_perf_test_results
ORDER BY step;

PROMPT
PROMPT ============================================================
PROMPT  Done. Query results anytime:
PROMPT    SELECT * FROM pa_perf_test_results ORDER BY step;
PROMPT ============================================================

-- =============================================================================
-- MONITORING (run in a SEPARATE session during step 4):
--
-- SELECT sid, serial#, opname, target, sofar, totalwork,
--        ROUND(sofar/NULLIF(totalwork,0)*100, 1) AS pct_done,
--        time_remaining
-- FROM v$session_longops
-- WHERE time_remaining > 0;
-- =============================================================================

-- =============================================================================
-- CLEANUP (uncomment when done):
-- DROP TABLE pa_activation_perf_test;
-- DROP TABLE pa_perf_test_results;
-- =============================================================================
