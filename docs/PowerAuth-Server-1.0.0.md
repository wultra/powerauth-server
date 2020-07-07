# Migration from 0.24.0 to 1.0.0

This guide contains instructions for migration from PowerAuth Server version `0.24.0` to version `1.0.0`.

## Database Changes

Following DB changes occurred between version 0.24.0 and 1.0.0:
- Table `pa_activation` - added column `flags`.
- Table `pa_application` - added column `roles`.

Migration script for Oracle:

```sql
ALTER TABLE "PA_ACTIVATION" ADD "FLAGS" VARCHAR2(255 CHAR);
ALTER TABLE "PA_APPLICATION" ADD "ROLES" VARCHAR2(255 CHAR);
```

Migration script for MySQL:

```sql
ALTER TABLE `pa_activation` ADD `flags` varchar(255);
ALTER TABLE `pa_application` ADD `roles` varchar(255);
```

Migration script for PostgreSQL:

```sql
ALTER TABLE "pa_activation" ADD "flags" VARCHAR(255);
ALTER TABLE "pa_application" ADD "roles" VARCHAR(255);
```
