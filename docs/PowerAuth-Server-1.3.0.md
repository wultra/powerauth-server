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

## Extended Activation Expiration

<!-- begin box warning -->
This change may have security implications for your deployment. Please read through the description carefully.
<!-- end -->

We extended the default activation expiration interval from 2 minutes to 5 minutes. This means that there is a larger time frame between creating the activation (`initActivation`) and committing it (`commitActivation`) on the server side. We made this change because of a repeated feedback from the developers and testers, who struggled to perform necessary tasks within the 2-minute interval in a non-production environment which - unlike the production setup - is not frictionless.

We consider the 5-minute interval to still be safe, since the relatively high activation code entropy does not allow for a simple brute force attacks. However, should you have any security concerns, you can change the activation expiration time interval back to 2 minutes by setting the following property:

```
powerauth.service.crypto.activationValidityInMilliseconds=120000
```
