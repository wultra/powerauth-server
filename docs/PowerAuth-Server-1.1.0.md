# Migration from 1.0.x to 1.1.x

This guide contains instructions for migration from PowerAuth Server version `1.0.x` to version `1.1.x`.

## Partial Package Name Migration

Our original package name used to start with `io.getlime.*`. In `1.1.x`, we partially migrated our components to a new package name `com.wultra.*`, while some components still use the legacy package name. When autowiring dependencies, make sure to account for both package name if needed:

```java
@Configuration
@ComponentScan(basePackages = {"io.getlime.security.powerauth","com.wultra.security.powerauth"})
public class PowerAuthWebServiceConfiguration {
}
```

In case you do not provide the component scan hints mentioned above, you may see issues with autowiring, i.e.:

```
Parameter 0 of method setAuthenticationProvider in io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthAnnotationInterceptor required a bean of type 'io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider' that could not be found.

Action:
Consider defining a bean of type 'io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider' in your configuration.
```

## Embedded Bouncy Castle Library (Version 1.68)

Bouncy Castle library has been updated to version `1.68` and it is now **included directly in the application bundle (\*.war)**.

You can now safely remove any previous configurations of Bouncy Castle library you made earlier, such as installing BC globally inside JRE, putting it in the container's `lib` folder, or creating JBoss or Wildfly modules.  

## Apply Database Hotfix

We renamed the `POSTCARD_PRIVATE_KEY_ENCRYPTION` column to `POSTCARD_PRIV_KEY_ENCRYPTION` in 1.0.1 bugfix version to account for the 30-character limit in the Oracle databases. If you are upgrading directly from 1.0.0 version and still use the old column name, make sure to apply the following additional change:

### MySQL

 ```sql
ALTER TABLE pa_recovery_config
    CHANGE postcard_private_key_encryption postcard_priv_key_encryption
    INT DEFAULT 0 NOT NULL;
```

### PostgreSQL

```sql
ALTER TABLE pa_recovery_config
    RENAME COLUMN postcard_private_key_encryption TO postcard_priv_key_encryption;
```

### Oracle

```sql
ALTER TABLE pa_recovery_config
    RENAME COLUMN postcard_private_key_encryption TO postcard_priv_key_encryption;
```

## New Operation Structures

We added a concept of "operation" to PowerAuth Server. Operation is a high-level entity representing the signed request that can be used as a helper utility in case of operation approvals. To accommodate this feature, you need to create a new sequences, tables and indexes:

### MySQL

```sql
CREATE TABLE pa_operation (
    id varchar(37) NOT NULL,
    user_id varchar(255) NOT NULL,
    application_id bigint(20) NOT NULL,
    external_id varchar(255) NULL,
    operation_type varchar(255) NOT NULL,
    data text NOT NULL,
    parameters text NULL,
    status int(11) NOT NULL,
    signature_type varchar(255) NOT NULL,
    failure_count bigint(20) default 0 NOT NULL,
    max_failure_count bigint(20) NOT NULL,
    timestamp_created datetime NOT NULL,
    timestamp_expires datetime NOT NULL,
    timestamp_finalized datetime NULL,
    PRIMARY KEY (id),
    CONSTRAINT `FK_OPERATION_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE pa_operation_template (
    id bigint(20) NOT NULL,
    template_name varchar(255) NOT NULL,
    operation_type varchar(255) NOT NULL,
    data_template varchar(255) NOT NULL,
    signature_type varchar(255) NOT NULL,
    max_failure_count bigint(20) NOT NULL,
    expiration bigint(20) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE INDEX pa_operation_user ON pa_operation(user_id);

CREATE INDEX pa_operation_ts_created_idx ON pa_operation(timestamp_created);

CREATE INDEX pa_operation_ts_expires_idx ON pa_operation(timestamp_expires);

CREATE INDEX pa_operation_template_name_idx ON pa_operation_template(template_name);
```

### PostgreSQL

```sql
CREATE SEQUENCE "pa_operation_template_seq" MINVALUE 1 MAXVALUE 9223372036854775807 INCREMENT BY 1 START WITH 1 CACHE 20;

CREATE TABLE "pa_operation" (
    "id"                    VARCHAR(37) NOT NULL PRIMARY KEY,
    "user_id"               VARCHAR(255) NOT NULL,
    "application_id"        BIGINT NOT NULL,
    "external_id"           VARCHAR(255),
    "operation_type"        VARCHAR(255) NOT NULL,
    "data"                  TEXT NOT NULL,
    "parameters"            TEXT,
    "status"                INTEGER NOT NULL,
    "signature_type"        VARCHAR(255) NOT NULL,
    "failure_count"         BIGINT DEFAULT 0 NOT NULL,
    "max_failure_count"     BIGINT NOT NULL,
    "timestamp_created"     TIMESTAMP NOT NULL,
    "timestamp_expires"     TIMESTAMP NOT NULL,
    "timestamp_finalized"   TIMESTAMP
);

CREATE TABLE "pa_operation_template" (
    "id"                    BIGINT NOT NULL PRIMARY KEY,
    "template_name"         VARCHAR(255) NOT NULL,
    "operation_type"        VARCHAR(255) NOT NULL,
    "data_template"         VARCHAR(255) NOT NULL,
    "signature_type"        VARCHAR(255) NOT NULL,
    "max_failure_count"     BIGINT NOT NULL,
    "expiration"            BIGINT NOT NULL
);

ALTER TABLE "pa_operation" ADD CONSTRAINT "operation_application_fk" FOREIGN KEY ("application_id") REFERENCES "pa_application" ("id");

CREATE INDEX PA_OPERATION_USER ON PA_OPERATION(USER_ID);

CREATE INDEX PA_OPERATION_TS_CREATED_IDX ON PA_OPERATION(TIMESTAMP_CREATED);

CREATE INDEX PA_OPERATION_TS_EXPIRES_IDX ON PA_OPERATION(TIMESTAMP_EXPIRES);

CREATE INDEX PA_OPERATION_TEMPLATE_NAME_IDX ON PA_OPERATION_TEMPLATE(TEMPLATE_NAME);
```

### Oracle

```sql
CREATE SEQUENCE "PA_OPERATION_TEMPLATE_SEQ" MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;

CREATE TABLE "PA_OPERATION" (
    "ID"                    VARCHAR2(37 CHAR) NOT NULL PRIMARY KEY,
    "USER_ID"               VARCHAR2(255 CHAR) NOT NULL,
    "APPLICATION_ID"        NUMBER(19,0) NOT NULL,
    "EXTERNAL_ID"           VARCHAR2(255 CHAR),
    "OPERATION_TYPE"        VARCHAR2(255 CHAR) NOT NULL,
    "DATA"                  CLOB NOT NULL,
    "PARAMETERS"            CLOB,
    "STATUS"                NUMBER(10,0) NOT NULL,
    "SIGNATURE_TYPE"        VARCHAR(255 CHAR) NOT NULL,
    "FAILURE_COUNT"         NUMBER(19,0) DEFAULT 0 NOT NULL,
    "MAX_FAILURE_COUNT"     NUMBER(19,0) NOT NULL,
    "TIMESTAMP_CREATED"     TIMESTAMP(6) NOT NULL,
    "TIMESTAMP_EXPIRES"     TIMESTAMP(6) NOT NULL,
    "TIMESTAMP_FINALIZED"   TIMESTAMP(6)
);

CREATE TABLE "PA_OPERATION_TEMPLATE" (
    "ID"                    NUMBER(19,0) NOT NULL PRIMARY KEY,
    "TEMPLATE_NAME"         VARCHAR2(255 CHAR) NOT NULL,
    "OPERATION_TYPE"        VARCHAR2(255 CHAR) NOT NULL,
    "DATA_TEMPLATE"         VARCHAR2(255 CHAR) NOT NULL,
    "SIGNATURE_TYPE"        VARCHAR2(255 CHAR) NOT NULL,
    "MAX_FAILURE_COUNT"     NUMBER(19,0) NOT NULL,
    "EXPIRATION"            NUMBER(19,0) NOT NULL
);

ALTER TABLE "PA_OPERATION" ADD CONSTRAINT "OPERATION_APPLICATION_FK" FOREIGN KEY ("APPLICATION_ID") REFERENCES "PA_APPLICATION" ("ID") ENABLE;

CREATE INDEX PA_OPERATION_USER ON PA_OPERATION(USER_ID);

CREATE INDEX PA_OPERATION_TS_CREATED_IDX ON PA_OPERATION(TIMESTAMP_CREATED);

CREATE INDEX PA_OPERATION_TS_EXPIRES_IDX ON PA_OPERATION(TIMESTAMP_EXPIRES);

CREATE INDEX PA_OPERATION_TEMPLATE_NAME_IDX ON PA_OPERATION_TEMPLATE(TEMPLATE_NAME);
```

## Multiple Callback Types

Beside the callbacks that trigger on activation status change, we also support callbacks that are related to the operation status change. Therefore, we added a column that specifies the callback type. The default value that preserves the current behavior is `ACTIVATION_STATUS_CHANGE` (a callback related to an activation status change), the new callback type for operation status change is `OPERATION_STATUS_CHANGE`.

### MySQL

```sql
ALTER TABLE pa_application_callback
	ADD type VARCHAR(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL;
```

### PostgreSQL

```sql
ALTER TABLE pa_application_callback
	ADD type VARCHAR(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL;
```

### Oracle

```sql
ALTER TABLE pa_application_callback
	ADD type VARCHAR2(64 CHAR) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL;
```

The `CreateCallbackUrlRequest` also now contains a new mandatory attribute `type` that can be either `ACTIVATION_STATUS_CHANGE` or `OPERATION_STATUS_CHANGE`.

## Add Synchronization Table for SchedLock

We also introduced new scheduled tasks that are synchronized via ShedLock. In PowerAuth Server, SchedLock uses JDBC connection to persist the lock. Therefore, you need to create a new synchronization table to accommodate the locking data.

### MySQL

```sql
CREATE TABLE shedlock (
    name        VARCHAR(64) NOT NULL,
    lock_until  TIMESTAMP(3) NOT NULL,
    locked_at   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    locked_by   VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### PostgreSQL

```sql
CREATE TABLE shedlock (
    name        VARCHAR(64)  NOT NULL PRIMARY KEY,
    lock_until  TIMESTAMP(3) NOT NULL,
    locked_at   TIMESTAMP(3) NOT NULL,
    locked_by   VARCHAR(255) NOT NULL
);
```

### Oracle

```sql
CREATE TABLE shedlock (
    name        VARCHAR(64) NOT NULL PRIMARY KEY,
    lock_until  TIMESTAMP NOT NULL,
    locked_at   TIMESTAMP NOT NULL,
    locked_by   VARCHAR(255) NOT NULL
);
```

## Spring Vault Configuration Change

The Spring Vault is no longer configured using `bootstrap.properties`. The configuration properties needs to be moved into the `application.properties` file.

In case you set the Spring Vault configuration externally, e.g. using the `powerauth-java-server.xml` configuration file for Tomcat, no change is required.

For more information see: https://github.com/spring-cloud/spring-cloud-vault/tree/v3.0.0-M5#client-side-usage
