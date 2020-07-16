# Migration from 0.24.0 to 1.0.0

This guide contains instructions for migration from PowerAuth Server version `0.24.0` to version `1.0.0`.

## Database Changes

Following DB changes occurred between version 0.24.0 and 1.0.0:
- Table `pa_activation` - added column `flags`.
- Table `pa_application` - added column `roles`.
- Table `pa_recovery_config` - added column `postcard_private_key_encryption`.

Migration script for Oracle:

```sql
ALTER TABLE "PA_ACTIVATION" ADD "FLAGS" VARCHAR2(255 CHAR);
ALTER TABLE "PA_APPLICATION" ADD "ROLES" VARCHAR2(255 CHAR);
ALTER TABLE "PA_RECOVERY_CONFIG" ADD "POSTCARD_PRIVATE_KEY_ENCRYPTION" NUMBER(10,0) DEFAULT 0 NOT NULL;
```

Migration script for MySQL:

```sql
ALTER TABLE `pa_activation` ADD `flags` varchar(255);
ALTER TABLE `pa_application` ADD `roles` varchar(255);
ALTER TABLE `pa_recovery_config` ADD `postcard_private_key_encryption` int(11) NOT NULL DEFAULT 0;
```

Migration script for PostgreSQL:

```sql
ALTER TABLE "pa_activation" ADD "flags" VARCHAR(255);
ALTER TABLE "pa_application" ADD "roles" VARCHAR(255);
ALTER TABLE "pa_application" ADD "postcard_private_key_encryption" INTEGER DEFAULT 0 NOT NULL;
```
