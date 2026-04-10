-- =============================================================================
-- PowerAuth pa_activation performance test — Create database
-- MS SQL Server
--
-- Run as sa or sysadmin:
--   sqlcmd -S <server> -U sa -P <password> -i pa_activation_perf_test_create_db.sql
-- =============================================================================

CREATE DATABASE pa_perf_test;
GO

CREATE LOGIN pa_perf_test_user WITH PASSWORD = 'Pa_Perf_Test_Password1!';
GO

USE pa_perf_test;
GO

CREATE USER pa_perf_test_user FOR LOGIN pa_perf_test_user;
GO

ALTER ROLE db_owner ADD MEMBER pa_perf_test_user;
GO

PRINT 'Database pa_perf_test created.';
PRINT '';
PRINT 'Run the performance test with:';
PRINT '  sqlcmd -S <server> -U pa_perf_test_user -P Pa_Perf_Test_Password1! -d pa_perf_test -i pa_activation_perf_test.sql';
PRINT '';
PRINT 'Drop the database when done:';
PRINT '  sqlcmd -S <server> -U sa -P <password> -i pa_activation_perf_test_drop_db.sql';
GO
