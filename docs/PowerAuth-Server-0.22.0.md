# Migration from 0.21.0 to 0.22.0

This guide contains instructions for migration from PowerAuth Server version `0.21.0` to version `0.22.0`.

## Java 11 Support

Java 11 no longer supports installing Bouncy Castle using library extension mechanism. PowerAuth no 
longer contains the Bouncy Castle library in war files to avoid classloader issues in some web containers (e.g. Tomcat). 

The Bouncy Castle provider needs to be installed using mechanism supported by the web container. 
See the [Installing Bouncy Castle](./Installing-Bouncy-Castle.md#installing-bouncy-castle-on-java-11) chapter in documentation.

### Tomcat on Java 11

We have tested PowerAuth on Tomcat `9.0.16` with Java 11, so please use this version or higher. Older versions of Tomcat may not work properly with Java 11. 

## Database Changes

Following DB changes occurred between version 0.21.0 and 0.22.0:
- Table `pa_activation_history` - added column `external_user_id`

Migration script for Oracle:
```sql
ALTER TABLE PA_ACTIVATION_HISTORY ADD EXTERNAL_USER_ID VARCHAR2(255 CHAR);
ALTER TABLE PA_ACTIVATION_HISTORY ADD BLOCKED_REASON VARCHAR2(255 CHAR);
```

Migration script for MySQL:
```sql
ALTER TABLE `pa_activation_history` ADD `blocked_reason` varchar(255);
ALTER TABLE `pa_activation_history` ADD `external_user_id` varchar(255);
```

Migration script for PostgreSQL:
```sql
ALTER TABLE pa_activation_history ADD blocked_reason VARCHAR(255);
ALTER TABLE pa_activation_history ADD external_user_id VARCHAR(255);
```

TODO: Recovery codes DDL

