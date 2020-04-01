# Migration from 0.23.0 to 0.24.0

This guide contains instructions for migration from PowerAuth Server version `0.23.0` to version `0.24.0`.

## Database Changes

Following DB changes occurred between version 0.23.0 and 0.24.0:
- Table `pa_activation` - added column `device_info`

Migration script for Oracle:

```sql
ALTER TABLE "PA_ACTIVATION" ADD "PLATFORM" VARCHAR2(255 CHAR);
ALTER TABLE "PA_ACTIVATION" ADD "DEVICE_INFO" VARCHAR2(255 CHAR);
```

Migration script for MySQL:

```sql
ALTER TABLE `pa_activation` ADD `platform` varchar(255);
ALTER TABLE `pa_activation` ADD `device_info` varchar(255);
```

Migration script for PostgreSQL:

```sql
ALTER TABLE "pa_activation" ADD "platform" VARCHAR(255);
ALTER TABLE "pa_activation" ADD "device_info" VARCHAR(255);
```

## Service Interface Changes

### Revoking Recovery Codes on Activation Removal

We added an optional `revokeRecoveryCodes` attribute to [activation
removal service call](./SOAP-Service-Methods.md#method-removeactivation).
This flag indicates if recovery codes that are associated with removed
activation should be also revoked. By default, the value of the flag is
`false`, hence omitting the flag results in the same behavior as before
this change.  