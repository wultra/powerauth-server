---
layout: page
title: Migration from 0.17.0 to 0.18.0
---

This guide contains instructions for migration from PowerAuth Server version 0.17.0 to version 0.18.0.

## Database changes

Following DB changes occurred between version 0.17.0 and 0.18.0:
* Table `pa_activation` - added column `blocked_reason`
* Table `pa_signature_audit` - added column `additional_info`
* Added table `pa_activation_history`

Migration scripts are available for Oracle and MySQL.

DB migration script for Oracle:
```sql
--
--  Added Column BLOCKED_REASON in Table PA_ACTIVATION
--

ALTER TABLE PA_ACTIVATION ADD BLOCKED_REASON VARCHAR2(255 CHAR) DEFAULT NULL;

--
--  Added Column ADDITIONAL_INFO in Table PA_SIGNATURE_AUDIT
--

ALTER TABLE PA_SIGNATURE_AUDIT ADD ADDITIONAL_INFO VARCHAR2(255 CHAR) DEFAULT NULL;

--
--  DDL for Table PA_ACTIVATION_HISTORY
--

CREATE TABLE "PA_ACTIVATION_HISTORY"
(
    "ID"                 NUMBER(19,0) NOT NULL PRIMARY KEY,
    "ACTIVATION_ID"      VARCHAR2(37 CHAR) NOT NULL,
    "ACTIVATION_STATUS"  NUMBER(10,0),
    "TIMESTAMP_CREATED"  TIMESTAMP (6) NOT NULL
);

--
--  Ref Constraints for Table PA_ACTIVATION_HISTORY
--
ALTER TABLE "PA_ACTIVATION_HISTORY" ADD CONSTRAINT "HISTORY_ACTIVATION_FK" FOREIGN KEY ("ACTIVATION_ID") REFERENCES "PA_ACTIVATION" ("ACTIVATION_ID") ENABLE;

--
--  Added Sequence for Activation History ID Generation
--

CREATE SEQUENCE "ACTIVATION_HISTORY_SEQ" MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
```

In case you create the table and sequence by a different user than owner of the PowerAuth schema, grant access to this table (change `powerauth` to actual DB schema name in case it differs in your deployment):
```sql
GRANT ALL PRIVILEGES ON powerauth.PA_APPLICATION_SEQ TO powerauth;
GRANT ALL PRIVILEGES ON powerauth.ACTIVATION_HISTORY_SEQ TO powerauth;
```

DB migration script for MySQL:
```sql
--
--  Added column blocked_reason in table pa_activation
--

ALTER TABLE `pa_activation` ADD COLUMN `blocked_reason` VARCHAR(255);

--
--  Added column additional_info in table pa_signature_audit
--

ALTER TABLE `pa_signature_audit` ADD COLUMN `additional_info` VARCHAR(255);

--
-- Create table for activation changes
--

CREATE TABLE `pa_activation_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `K_HISTORY_ACTIVATION_ID` (`activation_id`),
  CONSTRAINT `FK_HISTORY_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

## Configuration changes

We added row level DB locking for activations when handling concurrent signature validation requests. The change requires configuration of DB lock timeout, we added a property for this to `application.properties`:

```properties
# Database Lock Timeout Configuration
javax.persistence.lock.timeout=10000
```

Locking of database records on Oracle unfortunately produces "follow-on-locking" warnings. These warnings can be safely ignored. To disable follow-on-locking warnings, we set the following property:

```properties
# Disabled follow-on-locking warnings
logging.level.org.hibernate.loader.Loader=ERROR
```

The issues is discussed here:
https://stackoverflow.com/questions/40115158/how-to-make-hibernate-lock-annotation-work-for-oracle-db
The issue is resolved in Hibernate 5.2.1, so this workaround will not be needed in the future once we migrate to newer version of Hibernate. You can set the more detailed logging level by overriding our properties.

In case you do not use our `application.properties` and configure PowerAuth server by other means, please make sure to add this property to configuration as well.
