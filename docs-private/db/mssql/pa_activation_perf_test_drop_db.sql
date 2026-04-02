-- =============================================================================
-- PowerAuth pa_activation performance test — Drop database
-- MS SQL Server
--
-- Run as sa or sysadmin:
--   sqlcmd -S <server> -U sa -P <password> -i pa_activation_perf_test_drop_db.sql
-- =============================================================================

USE master;
GO

ALTER DATABASE pa_perf_test SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
GO

DROP DATABASE pa_perf_test;
GO

DROP LOGIN pa_perf_test_user;
GO

PRINT 'Database pa_perf_test and login pa_perf_test_user dropped.';
GO
