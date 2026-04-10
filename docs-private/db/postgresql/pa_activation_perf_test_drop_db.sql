-- =============================================================================
-- PowerAuth pa_activation performance test — Drop database
-- PostgreSQL
--
-- Run as a superuser:
--   psql -U postgres -f pa_activation_perf_test_drop_db.sql
-- =============================================================================

DROP DATABASE IF EXISTS pa_perf_test;
DROP USER IF EXISTS pa_perf_test_user;

\echo 'Database pa_perf_test and user pa_perf_test_user dropped.'
