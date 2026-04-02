-- =============================================================================
-- PowerAuth pa_activation — Performance test: unique constraint on 10M rows
-- MS SQL Server
--
-- Simulates the migration scenario:
--   1. Table with 10M rows and only a non-unique single-column index (pa_activation_code)
--   2. Step 1: Add NOT NULL on activation_code
--   3. Step 2: Add unique constraint (application_id, activation_code)
--   4. Step 3: Drop old non-unique index
--
-- Run with: sqlcmd -S <server> -U pa_perf_test_user -P Pa_Perf_Test_Password1! -d pa_perf_test -i pa_activation_perf_test.sql
-- Monitor index build progress in a separate session (see MONITORING section at the bottom).
--
-- Results are stored in pa_perf_test_results and can be queried after the run:
--   SELECT * FROM pa_perf_test_results ORDER BY step;
--
-- Note: duration is stored in milliseconds (BIGINT) — SQL Server has no INTERVAL type.
-- =============================================================================

SET NOCOUNT ON;
PRINT '';
PRINT '============================================================';
PRINT ' PowerAuth pa_activation constraint performance test';
PRINT '============================================================';
GO

-- -----------------------------------------------------------------------------
-- 1. SETUP: Drop existing tables, create results table and test table.
--    activation_code is intentionally NULLABLE to simulate the current state.
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [1/6] Creating test tables ---';
GO

DROP TABLE IF EXISTS pa_activation_perf_test;
DROP TABLE IF EXISTS pa_perf_test_results;
GO

-- Results table — persists all measurements after the script finishes
-- Note: duration stored as milliseconds (BIGINT) — no INTERVAL type in SQL Server
CREATE TABLE pa_perf_test_results (
    step        SMALLINT      NOT NULL,
    description VARCHAR(255)  NOT NULL,
    started_at  DATETIME2     NOT NULL,
    finished_at DATETIME2     NOT NULL,
    duration_ms BIGINT        NOT NULL
);
GO

CREATE TABLE pa_activation_perf_test (
    activation_id               varchar(37)   NOT NULL,
    application_id              int           NOT NULL,
    user_id                     varchar(255)  NOT NULL,
    activation_name             varchar(255),
    activation_code             varchar(255),              -- nullable (current state before migration)
    activation_status           int           NOT NULL,
    activation_otp              varchar(255),
    activation_otp_validation   int           CONSTRAINT DF_perf_otp_val    DEFAULT 0 NOT NULL,
    blocked_reason              varchar(255),
    counter                     int           NOT NULL,
    ctr_data                    varchar(255),
    device_public_key_base64    varchar(255),
    extras                      varchar(255),
    platform                    varchar(255),
    device_info                 varchar(255),
    flags                       varchar(255),
    failed_attempts             int           NOT NULL,
    max_failed_attempts         int           CONSTRAINT DF_perf_max_fail   DEFAULT 5 NOT NULL,
    server_private_key_base64   varchar(255)  NOT NULL,
    server_private_key_encryption int         CONSTRAINT DF_perf_pk_enc     DEFAULT 0 NOT NULL,
    server_public_key_base64    varchar(255)  NOT NULL,
    timestamp_activation_expire datetime2(6)  NOT NULL,
    timestamp_created           datetime2(6)  NOT NULL,
    timestamp_last_used         datetime2(6)  NOT NULL,
    timestamp_last_change       datetime2(6),
    master_keypair_id           int,
    version                     int           CONSTRAINT DF_perf_version     DEFAULT 2,
    CONSTRAINT pa_activation_perf_test_pk PRIMARY KEY (activation_id)
);
GO

-- Simulate the existing non-unique single-column index (starting state before migration)
CREATE INDEX pa_activation_perf_test_code_old ON pa_activation_perf_test(activation_code);
GO

-- -----------------------------------------------------------------------------
-- 2. DATA GENERATION: Insert 10,000,000 rows
--    activation_id:   NEWID() UUID (36 chars)
--    activation_code: XXXXX-XXXXX-XXXXX-XXXXX derived from row number (unique)
--    application_id:  spread across 10 apps
--    Uses a cross-join tally CTE to generate row numbers without loops.
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [2/6] Inserting 10,000,000 rows (this may take several minutes) ---';
GO

DECLARE @v_start DATETIME2 = SYSDATETIME();

WITH
    L0  AS (SELECT 1 n UNION ALL SELECT 1),
    L1  AS (SELECT 1 n FROM L0  a CROSS JOIN L0  b),
    L2  AS (SELECT 1 n FROM L1  a CROSS JOIN L1  b),
    L3  AS (SELECT 1 n FROM L2  a CROSS JOIN L2  b),
    L4  AS (SELECT 1 n FROM L3  a CROSS JOIN L3  b),
    L5  AS (SELECT 1 n FROM L4  a CROSS JOIN L4  b),
    Nums AS (SELECT TOP(10000000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) i FROM L5)
INSERT INTO pa_activation_perf_test (
    activation_id, application_id, user_id, activation_code,
    activation_status, activation_otp_validation, counter, failed_attempts,
    max_failed_attempts, server_private_key_base64, server_private_key_encryption,
    server_public_key_base64, timestamp_activation_expire, timestamp_created, timestamp_last_used
)
SELECT
    -- activation_id: standard UUID (36 chars)
    LOWER(CONVERT(varchar(36), NEWID())),
    -- application_id: 10 applications
    ((i - 1) % 10) + 1,
    -- user_id
    'user-' + CAST((i - 1) % 1000000 AS varchar),
    -- activation_code: XXXXX-XXXXX-XXXXX-XXXXX derived from i (globally unique)
    SUBSTRING(RIGHT(REPLICATE('0', 20) + CAST(i AS varchar), 20),  1, 5) + '-' +
    SUBSTRING(RIGHT(REPLICATE('0', 20) + CAST(i AS varchar), 20),  6, 5) + '-' +
    SUBSTRING(RIGHT(REPLICATE('0', 20) + CAST(i AS varchar), 20), 11, 5) + '-' +
    SUBSTRING(RIGHT(REPLICATE('0', 20) + CAST(i AS varchar), 20), 16, 5),
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
    0,   -- activation_otp_validation
    0,   -- counter
    0,   -- failed_attempts
    5,   -- max_failed_attempts
    LEFT(REPLACE(CONVERT(varchar(36), NEWID()), '-', ''), 44),  -- server_private_key_base64 (placeholder)
    0,   -- server_private_key_encryption
    LEFT(REPLACE(CONVERT(varchar(36), NEWID()), '-', ''), 44),  -- server_public_key_base64 (placeholder)
    DATEADD(MINUTE,  5, SYSDATETIME()),
    DATEADD(SECOND, -i, SYSDATETIME()),
    DATEADD(SECOND, -i, SYSDATETIME())
FROM Nums;

DECLARE @v_end DATETIME2 = SYSDATETIME();
DECLARE @duration_ms BIGINT = DATEDIFF(MILLISECOND, @v_start, @v_end);
INSERT INTO pa_perf_test_results VALUES (0, 'Data generation (10M rows)', @v_start, @v_end, @duration_ms);
PRINT 'Data generation completed in: ' + CAST(@duration_ms AS varchar) + ' ms';
GO

-- Quick sanity check
SELECT COUNT(*) AS total_rows FROM pa_activation_perf_test;
GO

-- -----------------------------------------------------------------------------
-- 3. MEASURE STEP 1: Add NOT NULL constraint on activation_code
--    Note: SQL Server requires the full column type when modifying nullability.
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [3/6] Step 1: Adding NOT NULL constraint on activation_code ---';
GO

DECLARE @v_start DATETIME2 = SYSDATETIME();
ALTER TABLE pa_activation_perf_test ALTER COLUMN activation_code varchar(255) NOT NULL;
DECLARE @v_end DATETIME2 = SYSDATETIME();
DECLARE @duration_ms BIGINT = DATEDIFF(MILLISECOND, @v_start, @v_end);
INSERT INTO pa_perf_test_results VALUES (1, 'ADD NOT NULL on activation_code', @v_start, @v_end, @duration_ms);
PRINT 'NOT NULL constraint added in: ' + CAST(@duration_ms AS varchar) + ' ms';
GO

-- -----------------------------------------------------------------------------
-- 4. MEASURE STEP 2: Add unique constraint on (application_id, activation_code)
--    This is the most expensive operation — builds a new B-tree index.
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [4/6] Step 2: Adding unique constraint (application_id, activation_code) ---';
PRINT '         Monitor progress in another session — see MONITORING section at the bottom.';
GO

DECLARE @v_start DATETIME2 = SYSDATETIME();
ALTER TABLE pa_activation_perf_test
    ADD CONSTRAINT pa_activation_perf_test_code_app_uk UNIQUE (application_id, activation_code);
DECLARE @v_end DATETIME2 = SYSDATETIME();
DECLARE @duration_ms BIGINT = DATEDIFF(MILLISECOND, @v_start, @v_end);
INSERT INTO pa_perf_test_results VALUES (2, 'ADD UNIQUE (application_id, activation_code)', @v_start, @v_end, @duration_ms);
PRINT 'Unique constraint added in: ' + CAST(@duration_ms AS varchar) + ' ms';
GO

-- -----------------------------------------------------------------------------
-- 5. MEASURE STEP 3: Drop old non-unique index
--    Note: SQL Server requires the table name in DROP INDEX.
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [5/6] Step 3: Dropping old non-unique index ---';
GO

DECLARE @v_start DATETIME2 = SYSDATETIME();
DROP INDEX pa_activation_perf_test_code_old ON pa_activation_perf_test;
DECLARE @v_end DATETIME2 = SYSDATETIME();
DECLARE @duration_ms BIGINT = DATEDIFF(MILLISECOND, @v_start, @v_end);
INSERT INTO pa_perf_test_results VALUES (3, 'DROP old non-unique index', @v_start, @v_end, @duration_ms);
PRINT 'Old index dropped in: ' + CAST(@duration_ms AS varchar) + ' ms';
GO

-- -----------------------------------------------------------------------------
-- 6. VERIFY: Confirm the constraint and indexes are in place
-- -----------------------------------------------------------------------------
PRINT '';
PRINT '--- [6/6] Verification ---';
GO

SELECT kc.name AS constraint_name, kc.type_desc AS type
FROM sys.key_constraints kc
JOIN sys.tables t ON kc.parent_object_id = t.object_id
WHERE t.name = 'pa_activation_perf_test';

SELECT i.name AS index_name, i.is_unique, i.type_desc
FROM sys.indexes i
JOIN sys.tables t ON i.object_id = t.object_id
WHERE t.name = 'pa_activation_perf_test' AND i.name IS NOT NULL
ORDER BY i.name;

-- Final results summary
PRINT '';
PRINT '--- Results summary (also persisted in pa_perf_test_results) ---';
GO

SELECT step, description, started_at, finished_at,
       CAST(duration_ms / 1000 AS varchar) + '.' + RIGHT('000' + CAST(duration_ms % 1000 AS varchar), 3) + ' s' AS duration
FROM pa_perf_test_results
ORDER BY step;
GO

PRINT '';
PRINT '============================================================';
PRINT ' Done. Query results anytime:';
PRINT '   SELECT * FROM pa_perf_test_results ORDER BY step;';
PRINT '============================================================';
GO

-- =============================================================================
-- MONITORING (run in a SEPARATE session during step 4):
--
-- SELECT r.percent_complete,
--        r.estimated_completion_time / 1000 AS estimated_remaining_sec,
--        r.command,
--        r.status
-- FROM sys.dm_exec_requests r
-- WHERE r.command IN ('ALTER TABLE', 'CREATE INDEX');
-- =============================================================================

-- =============================================================================
-- CLEANUP (uncomment when done):
-- DROP TABLE IF EXISTS pa_activation_perf_test;
-- DROP TABLE IF EXISTS pa_perf_test_results;
-- =============================================================================
