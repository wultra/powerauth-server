# Migration from 1.2.x to 1.3.x

This guide contains instructions for migration from PowerAuth Server version `1.2.x` to version `1.3.x`.

## Create New Columns in Operation Table

Create a new columns in the operations table:

- `template_name` - Stores the original template name.
- `activation_flag` - Stores the activation flag that must be present on activation in order to return / approve / reject the operation.
- `additional_data` - Stores attributes related to the approval / rejection / cancellation event.

### Oracle

```sql
ALTER TABLE PA_OPERATION ADD TEMPLATE_NAME VARCHAR2(255);

ALTER TABLE PA_OPERATION ADD ACTIVATION_FLAG VARCHAR2(255);

ALTER TABLE PA_OPERATION ADD AUTHENTICATION CLOB;
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