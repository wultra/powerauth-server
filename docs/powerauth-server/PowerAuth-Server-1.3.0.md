# Migration from 1.2.5 to 1.3.x

This guide contains instructions for migration from PowerAuth Server version `1.2.5` to version `1.3.x`.

Migration from release `1.2.x` of PowerAuth server to release `1.3.x` is split into two parts:
 - [Migration from 1.2.x to 1.2.5](./PowerAuth-Server-1.2.5.md) - apply these steps for upgrade to version `1.2.5`
 - Migration from 1.2.5 to 1.3.x (this document) - apply steps below for upgrade from version `1.2.5` to version `1.3.x`

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

## Extended Activation Expiration

<!-- begin box warning -->
This change may have security implications for your deployment. Please read through the description carefully.
<!-- end -->

We extended the default activation expiration interval from 2 minutes to 5 minutes. This means that there is a larger time frame between creating the activation (`initActivation`) and committing it (`commitActivation`) on the server side. We made this change because of a repeated feedback from the developers and testers, who struggled to perform necessary tasks within the 2-minute interval in a non-production environment which - unlike the production setup - is not frictionless.

We consider the 5-minute interval to still be safe, since the relatively high activation code entropy does not allow for a simple brute force attacks. However, should you have any security concerns, you can change the activation expiration time interval back to 2 minutes by setting the following property:

```
powerauth.service.crypto.activationValidityInMilliseconds=120000
```
