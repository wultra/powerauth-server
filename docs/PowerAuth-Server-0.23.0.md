# Migration from 0.22.0 to 0.23.0

This guide contains instructions for migration from PowerAuth Server version `0.22.0` to version `0.23.0`.

## Database Changes

Following DB changes occurred between version 0.22.0 and 0.23.0:
- Table `pa_application` - added not null constraint to column `name`, inserted default `application_%id` where null
- Table `pa_application` - added unique index constraint to column `name`
  - This index is mandatory. The script will fail when there are already duplicated names. In such case ensure unique
  values manually and repeat adding the unique index constraint.

Migration script for Oracle:
```sql
UPDATE "PA_APPLICATION" SET NAME = CONCAT('application_', id) WHERE NAME IS NULL;
ALTER TABLE "PA_APPLICATION" ALTER COLUMN NAME SET NOT NULL;
CREATE UNIQUE INDEX PA_APPLICATION_NAME ON PA_APPLICATION(NAME);
```

Migration script for MySQL:
```sql
UPDATE `pa_application` SET `name` = CONCAT('application_', `id`) WHERE `name` IS NULL;
ALTER TABLE `pa_application` ALTER COLUMN `name` SET NOT NULL;
CREATE UNIQUE INDEX `pa_application_name` ON `pa_application`(`name`);
```

Migration script for PostgreSQL:
```sql
UPDATE "pa_application" SET name = CONCAT('application_', id) WHERE name IS NULL;
ALTER TABLE "pa_application" ALTER COLUMN name SET NOT NULL;
CREATE UNIQUE INDEX PA_APPLICATION_NAME ON PA_APPLICATION(NAME);
```
