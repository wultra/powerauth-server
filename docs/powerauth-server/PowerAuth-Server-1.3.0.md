# Migration from 1.2.5 to 1.3.x

This guide contains instructions for migration from PowerAuth Server version `1.2.5` to version `1.3.x`.

Migration from release `1.2.x` of PowerAuth server to release `1.3.x` is split into two parts:

- [Migration from 1.2.x to 1.2.5](./PowerAuth-Server-1.2.5.md) - apply these steps for upgrade to version `1.2.5`
- Migration from 1.2.5 to 1.3.x (this document) - apply steps below for upgrade from version `1.2.5` to version `1.3.x`

## Database Changes

### Relation Between Operations and Applications

In a previous versions before 1.3.x, an operation could only be connected to one application. With 1.3.x, we introduced ability to add a single operation to multiple applications, and hence we are adding a new relation table. The script below creates such a table and sets the original `pa_operation.application_id` column to nullable. The original column is unused, but we recommend keeping it for audit purposes.   

#### PostgreSQL

```sql
ALTER TABLE pa_operation
    ALTER COLUMN application_id DROP NOT NULL;

CREATE TABLE pa_operation_application (
    application_id INTEGER     NOT NULL,
    operation_id   VARCHAR(37) NOT NULL,
    CONSTRAINT pa_operation_application_pk PRIMARY KEY (application_id, operation_id)
);
```

#### Oracle

```sql
ALTER TABLE pa_operation
    MODIFY (application_id NULL);

CREATE TABLE pa_operation_application (
    application_id NUMBER(19,0) NOT NULL,
    operation_id   VARCHAR(37)  NOT NULL,
    CONSTRAINT pa_operation_application_pk PRIMARY KEY (application_id, operation_id)
);
```

#### MySQL

```sql
ALTER TABLE pa_operation
    MODIFY application_id BIGINT(20);

CREATE TABLE pa_operation_application (
    application_id BIGINT(20)  NOT NULL,
    operation_id   VARCHAR(37) NOT NULL,
    CONSTRAINT pa_operation_application_pk PRIMARY KEY (application_id, operation_id)
);
```

### Store Activation Version History

#### PostgreSQL

```sql
ALTER TABLE pa_activation_history
    ADD activation_version INTEGER;
```

#### Oracle

```sql
ALTER TABLE pa_activation_history
    ADD activation_version NUMBER(2,0);
```

#### MySQL

```sql
ALTER TABLE pa_activation_history
    ADD activation_version INT(2);
```

## Uniqueness Check on Application Versions

Until 1.3.x version, the `pa_application_version` could contain versions of the same name for a given application. This would be a rare setup, but it needs to be reviewed before the update to 1.3.x and above. First, run the following query:

```sql
SELECT name, application_id, count(*) FROM pa_application_version GROUP BY name, application_id ORDER BY count(*);
```

If you can see a version with more than one duplicates, manually rename such versions in the database so that the name is unique and run the above query again. To prevent any future version duplicities, we also recommend creating the following unique index:

### PostgreSQL

```sql
CREATE UNIQUE INDEX pa_application_name_index
    ON pa_application_version (application_id, name);
```

### Oracle

```sql
CREATE UNIQUE INDEX pa_application_name_index
    ON pa_application_version (application_id, name);
```

### MySQL

```sql
CREATE UNIQUE INDEX pa_application_name_index
    ON pa_application_version (application_id, name);
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

## Extended Activation Expiration

<!-- begin box warning -->
This change may have security implications for your deployment. Please read through the description carefully.
<!-- end -->

We extended the default activation expiration interval from 2 minutes to 5 minutes. This means that there is a larger time frame between creating the activation (`initActivation`) and committing it (`commitActivation`) on the server side. We made this change because of a repeated feedback from the developers and testers, who struggled to perform necessary tasks within the 2-minute interval in a non-production environment which - unlike the production setup - is not frictionless.

We consider the 5-minute interval to still be safe, since the relatively high activation code entropy does not allow for a simple brute force attacks. However, should you have any security concerns, you can change the activation expiration time interval back to 2 minutes by setting the following property:

```
powerauth.service.crypto.activationValidityInMilliseconds=120000
```

## Database Dialect Configuration

The latest release of PowerAuth requires configuration of database dialect.

The dialect is specified using following configuration property:
```properties
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
```

Use the most specific dialect, if possible, such as:
- `org.hibernate.dialect.Oracle12cDialect` for Oracle 12c or higher
- `org.hibernate.dialect.PostgreSQL95Dialect` for PostgreSQL 9.5 or higher

You can find additional database dialects in Hibernate documentation.
