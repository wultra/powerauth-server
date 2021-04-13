# Migration from 1.0.x to 1.1.x

This guide contains instructions for migration from PowerAuth Server version `1.0.x` to version `1.1.x`.

## Bouncy Castle Library Update to Version 1.68

Bouncy Castle library has been updated to version `1.68`. The newest version of Bouncy Castle library can be downloaded from: [https://www.bouncycastle.org/download/bcprov-jdk15on-168.jar](https://www.bouncycastle.org/download/bcprov-jdk15on-168.jar)

Installation on **Java 8**:
- Update Bouncy Castle library the `lib/ext` folder of the Java runtime

Installation on **Java 11**:
- Tomcat: update Bouncy Castle library in `CATALINA_HOME/lib`
- JBoss / Wildfly: update Bouncy Castle library global module
- Other web containers: follow instructions for installing a global library for the web container

For more details about installation of the library see [Installing Bouncy Castle](./Installing-Bouncy-Castle.md).

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