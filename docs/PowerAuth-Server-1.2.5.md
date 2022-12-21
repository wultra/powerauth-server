# Migration from 1.2.x to 1.2.5

This guide contains instructions for migration from PowerAuth Server version `1.2.x` to version `1.2.5`.

_Warning: release `1.2.5` of PowerAuth server requires application of database migration steps. Usually we do not require a database migration for minor releases, however in release `1.2.5` such migration is necessary._

## Create New Columns in Operation Table

Create a new columns in the operations table:

- `template_name` - Stores the original template name.
- `activation_flag` - Stores the activation flag that must be present on activation in order to return / approve / reject the operation.
- `additional_data` - Stores attributes related to the approval / rejection / cancellation event.

### Oracle

```sql
ALTER TABLE PA_OPERATION ADD TEMPLATE_NAME VARCHAR2(255);

ALTER TABLE PA_OPERATION ADD ACTIVATION_FLAG VARCHAR2(255);

ALTER TABLE PA_OPERATION ADD ADDITIONAL_DATA CLOB;
```

### PostgreSQL

```sql
ALTER TABLE pa_operation ADD template_name VARCHAR(255);

ALTER TABLE pa_operation ADD activation_flag VARCHAR(255);

ALTER TABLE pa_operation ADD additional_data TEXT;
```

### MySQL

```sql
ALTER TABLE pa_operation ADD template_name VARCHAR(255) NULL;

ALTER TABLE pa_operation ADD activation_flag VARCHAR(255) NULL;

ALTER TABLE pa_operation ADD additional_data TEXT NULL;
```

## Create New Column in Activation History Table

The `pa_activation_history` table was updated to include activation version.

### Oracle

```sql
ALTER TABLE PA_ACTIVATION_HISTORY ADD activation_version NUMBER(2,0);
```

### PostgreSQL

```sql
ALTER TABLE pa_activation_history ADD activation_version INTEGER;
```

### MySQL

```sql
ALTER TABLE pa_activation_history ADD activation_version int(2);
```
