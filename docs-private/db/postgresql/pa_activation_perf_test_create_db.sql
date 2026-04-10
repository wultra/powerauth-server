-- =============================================================================
-- PowerAuth pa_activation performance test — Create database
-- PostgreSQL
--
-- Run as a superuser:
--   psql -U postgres -f pa_activation_perf_test_create_db.sql
-- =============================================================================

-- Create dedicated user for the test
CREATE USER pa_perf_test_user WITH PASSWORD 'pa_perf_test_password';

-- Create dedicated database
CREATE DATABASE pa_perf_test
    WITH OWNER = pa_perf_test_user
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TEMPLATE = template0;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE pa_perf_test TO pa_perf_test_user;

\echo ''
\echo 'Database pa_perf_test created.'
\echo ''
\echo 'Run the performance test with:'
\echo '  psql -U pa_perf_test_user -d pa_perf_test -f pa_activation_perf_test.sql'
\echo ''
\echo 'Drop the database when done:'
\echo '  psql -U postgres -f pa_activation_perf_test_drop_db.sql'
