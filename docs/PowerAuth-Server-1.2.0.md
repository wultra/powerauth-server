# Migration from 1.1.x to 1.2.x

This guide contains instructions for migration from PowerAuth Server version `1.1.x` to version `1.2.x`.

## Database Changes

The `pa_application_callback` table was updated to include request authentication. 

### Oracle

```sql
ALTER TABLE "PA_APPLICATION_CALLBACK" ADD "AUTHENTICATION" CLOB;
```

### PostgreSQL

```sql
ALTER TABLE "pa_application_callback" ADD "authentication" TEXT;
```

### MySQL

```sql
ALTER TABLE `pa_application_callback` ADD `authentication` TEXT;
```
