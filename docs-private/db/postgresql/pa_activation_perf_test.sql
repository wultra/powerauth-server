-- =============================================================================
-- PowerAuth pa_activation — Performance test: unique constraint on 10M rows
-- PostgreSQL
--
-- Simulates the migration scenario:
--   1. Table with 10M rows and only a non-unique single-column index (pa_activation_code)
--   2. Step 1: Add NOT NULL on activation_code
--   3. Step 2: Add unique constraint (application_id, activation_code)
--   4. Step 3: Drop old non-unique index
--
-- Run with: psql -U <user> -d <database> -f pa_activation_perf_test.sql
-- Monitor index build progress in a separate session (see the MONITORING section at the bottom).
--
-- Results are stored in pa_perf_test_results and can be queried after the run:
--   SELECT * FROM pa_perf_test_results ORDER BY started_at;
-- =============================================================================

\timing on
\echo ''
\echo '============================================================'
\echo ' PowerAuth pa_activation constraint performance test'
\echo '============================================================'

-- -----------------------------------------------------------------------------
-- 1. SETUP: Create isolated test table (mirrors pa_activation, no FKs)
--    activation_code is intentionally NULLABLE to simulate the current state.
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [1/6] Creating test table ---'

DROP TABLE IF EXISTS pa_activation_perf_test;
DROP TABLE IF EXISTS pa_perf_test_results;

-- Results table — persists all measurements after the script finishes
CREATE TABLE pa_perf_test_results (
    step        SMALLINT     NOT NULL,
    description VARCHAR(255) NOT NULL,
    started_at  TIMESTAMP    NOT NULL,
    finished_at TIMESTAMP    NOT NULL,
    duration    INTERVAL     NOT NULL
);

CREATE TABLE pa_activation_perf_test (
    activation_id               VARCHAR(37)   NOT NULL,
    application_id              INTEGER       NOT NULL,
    user_id                     VARCHAR(255)  NOT NULL,
    activation_name             VARCHAR(255),
    activation_code             VARCHAR(255),              -- nullable (current state before migration)
    activation_status           INTEGER       NOT NULL,
    activation_otp              VARCHAR(255),
    activation_otp_validation   INTEGER       NOT NULL DEFAULT 0,
    blocked_reason              VARCHAR(255),
    counter                     INTEGER       NOT NULL,
    ctr_data                    VARCHAR(255),
    device_public_key_base64    VARCHAR(255),
    extras                      VARCHAR(255),
    platform                    VARCHAR(255),
    device_info                 VARCHAR(255),
    flags                       VARCHAR(255),
    failed_attempts             INTEGER       NOT NULL,
    max_failed_attempts         INTEGER       NOT NULL DEFAULT 5,
    server_private_key_base64   VARCHAR(255)  NOT NULL,
    server_private_key_encryption INTEGER     NOT NULL DEFAULT 0,
    server_public_key_base64    VARCHAR(255)  NOT NULL,
    timestamp_activation_expire TIMESTAMP(6)  NOT NULL,
    timestamp_created           TIMESTAMP(6)  NOT NULL,
    timestamp_last_used         TIMESTAMP(6)  NOT NULL,
    timestamp_last_change       TIMESTAMP(6),
    master_keypair_id           INTEGER,
    version                     INTEGER       DEFAULT 2,
    CONSTRAINT pa_activation_perf_test_pkey PRIMARY KEY (activation_id)
);

-- Simulate the existing non-unique single-column index (starting state before migration)
CREATE INDEX pa_activation_perf_test_code_old ON pa_activation_perf_test(activation_code);

-- -----------------------------------------------------------------------------
-- 2. DATA GENERATION: Insert 10,000,000 rows
--    activation_code: unique per (application_id, row) via md5(app_id || row_number)
--    application_id: spread across 10 apps to simulate realistic distribution
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [2/6] Inserting 10,000,000 rows (this may take a few minutes) ---'

DO $$
DECLARE
    v_start TIMESTAMP := clock_timestamp();
    v_end   TIMESTAMP;
BEGIN
    INSERT INTO pa_activation_perf_test (
        activation_id,
        application_id,
        user_id,
        activation_code,
        activation_status,
        activation_otp_validation,
        counter,
        failed_attempts,
        max_failed_attempts,
        server_private_key_base64,
        server_private_key_encryption,
        server_public_key_base64,
        timestamp_activation_expire,
        timestamp_created,
        timestamp_last_used
    )
    SELECT
        -- activation_id: standard UUID (36 chars, fits VARCHAR(37))
        gen_random_uuid()::text,
        -- application_id: 10 applications
        (i % 10) + 1,
        -- user_id
        'user-' || (i % 1000000),
        -- activation_code: XXXXX-XXXXX-XXXXX-XXXXX (unique per app+row via md5)
        upper(substr(md5((i % 10 + 1)::text || '-' || i::text), 1, 5))  || '-' ||
        upper(substr(md5((i % 10 + 1)::text || '-' || i::text), 6, 5))  || '-' ||
        upper(substr(md5((i % 10 + 1)::text || '-' || i::text), 11, 5)) || '-' ||
        upper(substr(md5((i % 10 + 1)::text || '-' || i::text), 16, 5)),
        -- activation_status: realistic mix (1=CREATED, 3=ACTIVE, 4=REMOVED, 5=BLOCKED)
        CASE (i % 10)
            WHEN 0 THEN 1   -- 10% CREATED
            WHEN 1 THEN 1
            WHEN 2 THEN 3   -- 50% ACTIVE
            WHEN 3 THEN 3
            WHEN 4 THEN 3
            WHEN 5 THEN 3
            WHEN 6 THEN 3
            WHEN 7 THEN 4   -- 30% REMOVED
            WHEN 8 THEN 4
            ELSE 5          -- 10% BLOCKED
        END,
        0,  -- activation_otp_validation
        0,  -- counter
        0,  -- failed_attempts
        5,  -- max_failed_attempts
        substr(md5(i::text || 'priv'), 1, 44),  -- server_private_key_base64 (placeholder)
        0,  -- server_private_key_encryption
        substr(md5(i::text || 'pub'), 1, 44),   -- server_public_key_base64 (placeholder)
        NOW() + interval '5 minutes',
        NOW() - (i || ' seconds')::interval,
        NOW() - (i || ' seconds')::interval
    FROM generate_series(1, 10000000) AS s(i);

    v_end := clock_timestamp();
    INSERT INTO pa_perf_test_results VALUES (0, 'Data generation (10M rows)', v_start, v_end, v_end - v_start);
    RAISE NOTICE 'Data generation completed in: %', (v_end - v_start);
END;
$$;

-- Quick sanity check
SELECT COUNT(*) AS total_rows FROM pa_activation_perf_test;

-- -----------------------------------------------------------------------------
-- 3. MEASURE STEP 1: Add NOT NULL constraint on activation_code
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [3/6] Step 1: Adding NOT NULL constraint on activation_code ---'

DO $$
DECLARE
    v_start TIMESTAMP := clock_timestamp();
    v_end   TIMESTAMP;
BEGIN
    ALTER TABLE pa_activation_perf_test
        ALTER COLUMN activation_code SET NOT NULL;
    v_end := clock_timestamp();
    INSERT INTO pa_perf_test_results VALUES (1, 'ADD NOT NULL on activation_code', v_start, v_end, v_end - v_start);
    RAISE NOTICE 'NOT NULL constraint added in: %', (v_end - v_start);
END;
$$;

-- -----------------------------------------------------------------------------
-- 4. MEASURE STEP 2: Add unique constraint on (application_id, activation_code)
--    This is the most expensive operation — builds a new B-tree index.
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [4/6] Step 2: Adding unique constraint (application_id, activation_code) ---'
\echo '         Monitor progress in another session — see MONITORING section at the bottom.'

DO $$
DECLARE
    v_start TIMESTAMP := clock_timestamp();
    v_end   TIMESTAMP;
BEGIN
    ALTER TABLE pa_activation_perf_test
        ADD CONSTRAINT pa_activation_perf_test_code_app_uk
        UNIQUE (application_id, activation_code);
    v_end := clock_timestamp();
    INSERT INTO pa_perf_test_results VALUES (2, 'ADD UNIQUE (application_id, activation_code)', v_start, v_end, v_end - v_start);
    RAISE NOTICE 'Unique constraint added in: %', (v_end - v_start);
END;
$$;

-- -----------------------------------------------------------------------------
-- 5. MEASURE STEP 3: Drop old non-unique index
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [5/6] Step 3: Dropping old non-unique index ---'

DO $$
DECLARE
    v_start TIMESTAMP := clock_timestamp();
    v_end   TIMESTAMP;
BEGIN
    DROP INDEX pa_activation_perf_test_code_old;
    v_end := clock_timestamp();
    INSERT INTO pa_perf_test_results VALUES (3, 'DROP old non-unique index', v_start, v_end, v_end - v_start);
    RAISE NOTICE 'Old index dropped in: %', (v_end - v_start);
END;
$$;

-- -----------------------------------------------------------------------------
-- 6. VERIFY: Confirm the constraint and indexes are in place
-- -----------------------------------------------------------------------------
\echo ''
\echo '--- [6/6] Verification ---'

SELECT
    conname   AS constraint_name,
    contype   AS type,
    pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conrelid = 'pa_activation_perf_test'::regclass
ORDER BY contype;

SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'pa_activation_perf_test'
ORDER BY indexname;

-- Final results summary
\echo ''
\echo '--- Results summary (also persisted in pa_perf_test_results) ---'

SELECT
    step,
    description,
    started_at,
    finished_at,
    duration
FROM pa_perf_test_results
ORDER BY step;

\echo ''
\echo '============================================================'
\echo ' Done. Query results anytime:'
\echo '   SELECT * FROM pa_perf_test_results ORDER BY step;'
\echo '============================================================'

-- =============================================================================
-- MONITORING (run in a SEPARATE psql session during step 4):
--
-- SELECT
--     phase,
--     blocks_done,
--     blocks_total,
--     ROUND(blocks_done::numeric / NULLIF(blocks_total, 0) * 100, 1) AS pct_done,
--     tuples_done,
--     tuples_total
-- FROM pg_stat_progress_create_index;
-- =============================================================================

-- =============================================================================
-- CLEANUP (uncomment when done):
-- DROP TABLE IF EXISTS pa_activation_perf_test;
-- DROP TABLE IF EXISTS pa_perf_test_results;
-- =============================================================================
