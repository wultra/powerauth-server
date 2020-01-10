# Migration from 0.23.0 to 0.24.0

This guide contains instructions for migration from PowerAuth Server version `0.23.0` to version `0.24.0`.

## Database Changes

Following DB changes occurred between version 0.23.0 and 0.24.0:
- Table `pa_activation` - added column `device_info`

Migration script for Oracle:
```sql
ALTER TABLE "PA_ACTIVATION" ADD "PLATFORM" VARCHAR2(255 CHAR);
ALTER TABLE "PA_ACTIVATION" ADD "DEVICE_INFO" VARCHAR2(255 CHAR);
```

Migration script for MySQL:
```sql
ALTER TABLE `pa_activation` ADD `platform` varchar(255);
ALTER TABLE `pa_activation` ADD `device_info` varchar(255);
```

Migration script for PostgreSQL:
```sql
ALTER TABLE "pa_activation" ADD "platform" VARCHAR(255);
ALTER TABLE "pa_activation" ADD "device_info" VARCHAR(255);
```
