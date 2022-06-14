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

## Create Auditing Tables

Create tables for auditing:
- `audit_log` - table used to store audit logs
- `audit_param` - table used to store detailed parameters for audit logs

### Oracle

```sql
--
-- Create audit log table.
--
CREATE TABLE audit_log (
    audit_log_id       VARCHAR2(36 CHAR) PRIMARY KEY,
    application_name   VARCHAR2(256 CHAR) NOT NULL,
    audit_level        VARCHAR2(32 CHAR) NOT NULL,
    audit_type         VARCHAR2(256 CHAR),
    timestamp_created  TIMESTAMP,
    message            CLOB NOT NULL,
    exception_message  CLOB,
    stack_trace        CLOB,
    param              CLOB,
    calling_class      VARCHAR2(256 CHAR) NOT NULL,
    thread_name        VARCHAR2(256 CHAR) NOT NULL,
    version            VARCHAR2(256 CHAR),
    build_time         TIMESTAMP
);

--
-- Create audit parameters table.
--
CREATE TABLE audit_param (
    audit_log_id       VARCHAR2(36 CHAR),
    timestamp_created  TIMESTAMP,
    param_key          VARCHAR2(256 CHAR),
    param_value        VARCHAR2(4000 CHAR)
);

--
-- Create indexes.
--
CREATE INDEX audit_log_timestamp ON audit_log (timestamp_created);
CREATE INDEX audit_log_application ON audit_log (application_name);
CREATE INDEX audit_log_level ON audit_log (audit_level);
CREATE INDEX audit_log_type ON audit_log (audit_type);
CREATE INDEX audit_param_log ON audit_param (audit_log_id);
CREATE INDEX audit_param_timestamp ON audit_param (timestamp_created);
CREATE INDEX audit_param_key ON audit_param (param_key);
CREATE INDEX audit_param_value ON audit_param (param_value);
```

### PostgreSQL

```sql
--
-- Create audit log table.
--
CREATE TABLE audit_log (
    audit_log_id       VARCHAR(36) PRIMARY KEY,
    application_name   VARCHAR(256) NOT NULL,
    audit_level        VARCHAR(32) NOT NULL,
    audit_type         VARCHAR(256),
    timestamp_created  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message            TEXT NOT NULL,
    exception_message  TEXT,
    stack_trace        TEXT,
    param              TEXT,
    calling_class      VARCHAR(256) NOT NULL,
    thread_name        VARCHAR(256) NOT NULL,
    version            VARCHAR(256),
    build_time         TIMESTAMP
);

--
-- Create audit parameters table.
--
CREATE TABLE audit_param (
    audit_log_id       VARCHAR(36),
    timestamp_created  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    param_key          VARCHAR(256),
    param_value        VARCHAR(4000)
);

--
-- Create indexes.
--
CREATE INDEX audit_log_timestamp ON audit_log (timestamp_created);
CREATE INDEX audit_log_application ON audit_log (application_name);
CREATE INDEX audit_log_level ON audit_log (audit_level);
CREATE INDEX audit_log_type ON audit_log (audit_type);
CREATE INDEX audit_param_log ON audit_param (audit_log_id);
CREATE INDEX audit_param_timestamp ON audit_param (timestamp_created);
CREATE INDEX audit_param_key ON audit_param (param_key);
CREATE INDEX audit_param_value ON audit_param (param_value);
```

### MySQL

```sql
--
-- Create audit log table.
--
CREATE TABLE audit_log (
    audit_log_id       VARCHAR(36) PRIMARY KEY,
    application_name   VARCHAR(256) NOT NULL,
    audit_level        VARCHAR(32) NOT NULL,
    audit_type         VARCHAR(256),
    timestamp_created  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message            TEXT NOT NULL,
    exception_message  TEXT,
    stack_trace        TEXT,
    param              TEXT,
    calling_class      VARCHAR(256) NOT NULL,
    thread_name        VARCHAR(256) NOT NULL,
    version            VARCHAR(256),
    build_time         TIMESTAMP NULL
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create audit parameters table.
--
CREATE TABLE audit_param (
    audit_log_id       VARCHAR(36),
    timestamp_created  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    param_key          VARCHAR(256),
    param_value        VARCHAR(3072)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create indexes.
--
CREATE INDEX audit_log_timestamp ON audit_log (timestamp_created);
CREATE INDEX audit_log_application ON audit_log (application_name);
CREATE INDEX audit_log_level ON audit_log (audit_level);
CREATE INDEX audit_log_type ON audit_log (audit_type);
CREATE INDEX audit_param_log ON audit_param (audit_log_id);
CREATE INDEX audit_param_timestamp ON audit_param (timestamp_created);
CREATE INDEX audit_param_key ON audit_param (param_key);
CREATE FULLTEXT INDEX audit_param_value ON audit_param (param_value);
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
