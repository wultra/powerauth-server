# Migration from 0.21.0 to 0.22.0

This guide contains instructions for migration from PowerAuth Server version `0.21.0` to version `0.22.0`.

## Bouncy Castle Library Update to Version 1.61

Bouncy Castle library has been updated to version `1.61`. PowerAuth server no longer contains the Bouncy Castle library in the war file,
thus the library needs to be updated in the `lib/ext` folder of Java runtime or web container libraries, depending on Java version.

The newest version of Bouncy Castle library can be downloaded from: [https://www.bouncycastle.org/download/bcprov-jdk15on-161.jar](https://www.bouncycastle.org/download/bcprov-jdk15on-161.jar)

Installation on **Java 8**:
- Update Bouncy Castle library the `lib/ext` folder of the Java runtime

Installation on **Java 11**:
- Tomcat: update Bouncy Castle library in `CATALINA_HOME/lib`
- JBoss / Wildfly: update Bouncy Castle library global module
- Other web containers: follow instructions for installing a global library for the web container
- Standalone mode: PowerAuth Server can no longer be started from command line because of missing Bouncy Castle library in the war file. Contact us if you want to run PowerAuth Server in standalone mode.

Additional requirements for Bouncy Castle library:
- Make sure that no other version of Bouncy Castle library is present in the web container
- Do not deploy additional applications (war files) which contain Bouncy Castle library in the same web container as PowerAuth due to potential classloader issues

For more details about installation of the library see [Installing Bouncy Castle](./Installing-Bouncy-Castle.md).

**Warning: PowerAuth Server requires Bouncy Castle version 1.61, do not use PowerAuth server with older versions of Bouncy Castle library.**

## Java 11 Support

The whole PowerAuth stack now supports Java 11. The deployment requirements for Java 11 are listed below.

### Bouncy Castle Library Deployment Change on Java 11

Java 11 no longer supports installing Bouncy Castle using library extension mechanism. PowerAuth no
longer contains the Bouncy Castle library in war files to avoid classloader issues in some web containers (e.g. Tomcat).

The Bouncy Castle provider needs to be installed using mechanism supported by the web container.
See the [Installing Bouncy Castle](./Installing-Bouncy-Castle.md#installing-on-java-11) chapter in documentation.

### Tomcat on Java 11

We have tested PowerAuth on Tomcat `9.0.16` with Java 11, so please use this version or higher. Older versions of Tomcat may not work properly with Java 11.

### Other Web Containers on Java 11

Make sure you upgrade the web container to a version which supports Java 11 before deploying PowerAuth server.

## Database Changes

Following DB changes occurred between version 0.21.0 and 0.22.0:
- Table `pa_activation_history` - added column `external_user_id`
- Added tables, sequences and indexes for storage of Recovery Codes, Recovery PUKs and Recovery Configuration

Migration script for Oracle:
```sql
ALTER TABLE PA_ACTIVATION_HISTORY ADD EXTERNAL_USER_ID VARCHAR2(255 CHAR);
ALTER TABLE PA_ACTIVATION_HISTORY ADD BLOCKED_REASON VARCHAR2(255 CHAR);

CREATE SEQUENCE "PA_RECOVERY_CODE_SEQ" MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE "PA_RECOVERY_PUK_SEQ" MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;
CREATE SEQUENCE "PA_RECOVERY_CONFIG_SEQ" MINVALUE 1 MAXVALUE 9999999999999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20 NOORDER NOCYCLE;

--
-- DDL for Table PA_RECOVERY_CODE
--

CREATE TABLE "PA_RECOVERY_CODE" (
    "ID"                    NUMBER(19,0) NOT NULL PRIMARY KEY,
    "RECOVERY_CODE"         VARCHAR2(23 CHAR) NOT NULL,
    "APPLICATION_ID"        NUMBER(19,0) NOT NULL,
    "USER_ID"               VARCHAR2(255 CHAR) NOT NULL,
    "ACTIVATION_ID"         VARCHAR2(37 CHAR),
    "STATUS"                NUMBER(10,0) NOT NULL,
    "FAILED_ATTEMPTS"       NUMBER(19,0) DEFAULT 0 NOT NULL,
    "MAX_FAILED_ATTEMPTS"   NUMBER(19,0) DEFAULT 10 NOT NULL,
    "TIMESTAMP_CREATED"     TIMESTAMP (6) NOT NULL,
    "TIMESTAMP_LAST_USED"   TIMESTAMP (6),
    "TIMESTAMP_LAST_CHANGE" TIMESTAMP (6)
);

--
-- DDL for Table PA_RECOVERY_PUK
--

CREATE TABLE "PA_RECOVERY_PUK" (
    "ID"                    NUMBER(19,0) NOT NULL PRIMARY KEY,
    "RECOVERY_CODE_ID"      NUMBER(19,0) NOT NULL,
    "PUK"                   VARCHAR2(255 CHAR),
    "PUK_ENCRYPTION"        NUMBER(10,0) DEFAULT 0 NOT NULL,
    "PUK_INDEX"             NUMBER(19,0) NOT NULL,
    "STATUS"                NUMBER(10,0) NOT NULL,
    "TIMESTAMP_LAST_CHANGE" TIMESTAMP (6)
);

--
-- DDL for Table PA_RECOVERY_CONFIG
--

CREATE TABLE "PA_RECOVERY_CONFIG" (
    "ID"                            NUMBER(19,0) NOT NULL PRIMARY KEY,
    "APPLICATION_ID"                NUMBER(19,0) NOT NULL,
    "ACTIVATION_RECOVERY_ENABLED"   NUMBER(1,0) DEFAULT 0 NOT NULL,
    "RECOVERY_POSTCARD_ENABLED"     NUMBER(1,0) DEFAULT 0 NOT NULL,
    "ALLOW_MULTIPLE_RECOVERY_CODES" NUMBER(1,0) DEFAULT 0 NOT NULL,    
    "POSTCARD_PRIVATE_KEY_BASE64"   VARCHAR2(255 CHAR),
    "POSTCARD_PUBLIC_KEY_BASE64"    VARCHAR2(255 CHAR),
    "REMOTE_PUBLIC_KEY_BASE64"      VARCHAR2(255 CHAR)
);

--
--  Ref Constraints for Table PA_RECOVERY_CODE
--
ALTER TABLE "PA_RECOVERY_CODE" ADD CONSTRAINT "RECOVERY_CODE_APPLICATION_FK" FOREIGN KEY ("APPLICATION_ID") REFERENCES "PA_APPLICATION" ("ID") ENABLE;
ALTER TABLE "PA_RECOVERY_CODE" ADD CONSTRAINT "RECOVERY_CODE_ACTIVATION_FK" FOREIGN KEY ("ACTIVATION_ID") REFERENCES "PA_ACTIVATION" ("ACTIVATION_ID") ENABLE;

--
--  Ref Constraints for Table PA_RECOVERY_PUK
--
ALTER TABLE "PA_RECOVERY_PUK" ADD CONSTRAINT "RECOVERY_PUK_CODE_FK" FOREIGN KEY ("RECOVERY_CODE_ID") REFERENCES "PA_RECOVERY_CODE" ("ID") ENABLE;

--
--  Ref Constraints for Table PA_RECOVERY_CONFIG
--
ALTER TABLE "PA_RECOVERY_CONFIG" ADD CONSTRAINT "RECOVERY_CONFIG_APP_FK" FOREIGN KEY ("APPLICATION_ID") REFERENCES "PA_APPLICATION" ("ID") ENABLE;


CREATE INDEX PA_RECOVERY_CODE ON PA_RECOVERY_CODE(RECOVERY_CODE);

CREATE INDEX PA_RECOVERY_CODE_APP ON PA_RECOVERY_CODE(APPLICATION_ID);

CREATE INDEX PA_RECOVERY_CODE_USER ON PA_RECOVERY_CODE(USER_ID);

CREATE INDEX PA_RECOVERY_CODE_ACT ON PA_RECOVERY_CODE(ACTIVATION_ID);

CREATE UNIQUE INDEX PA_RECOVERY_CODE_PUK ON PA_RECOVERY_PUK(RECOVERY_CODE_ID, PUK_INDEX);

CREATE INDEX PA_RECOVERY_PUK_CODE ON PA_RECOVERY_PUK(RECOVERY_CODE_ID);

CREATE UNIQUE INDEX PA_RECOVERY_CONFIG_APP ON PA_RECOVERY_CONFIG(APPLICATION_ID);
```

Migration script for MySQL:
```sql
ALTER TABLE `pa_activation_history` ADD `blocked_reason` varchar(255);
ALTER TABLE `pa_activation_history` ADD `external_user_id` varchar(255);
--
-- Create table for recovery codes
--

CREATE TABLE `pa_recovery_code` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `recovery_code` varchar(23) NOT NULL,
  `application_id` bigint(11) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `activation_id` varchar(37),
  `status` int(37) NOT NULL,
  `failed_attempts` int(11) NOT NULL,
  `max_failed_attempts` int(11) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `timestamp_last_used` datetime,
  `timestamp_last_change` datetime,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_RECOVERY_CODE_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `FK_RECOVERY_CODE_ACTIVATION` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for recovery code PUKs
--

CREATE TABLE `pa_recovery_puk` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `recovery_code_id` int(11) NOT NULL,
  `puk` varchar(255) NOT NULL,
  `puk_encryption` int(11) NOT NULL DEFAULT 0,
  `puk_index` int(11) NOT NULL,
  `status` int(37) NOT NULL,
  `timestamp_last_change` datetime,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_PUK_RECOVERY_CODE` FOREIGN KEY (`recovery_code_id`) REFERENCES `pa_recovery_code` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for recovery configuration
--
CREATE TABLE `pa_recovery_config` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `application_id` bigint(20) NOT NULL,
  `activation_recovery_enabled` int(1) NOT NULL DEFAULT 0,
  `recovery_postcard_enabled` int(1) NOT NULL DEFAULT 0,
  `allow_multiple_recovery_codes` int(1) NOT NULL DEFAULT 0,  
  `postcard_private_key_base64` varchar(255),
  `postcard_public_key_base64` varchar(255),
  `remote_public_key_base64` varchar(255),
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_RECOVERY_CONFIG_APP` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE INDEX `pa_recovery_code` ON `pa_recovery_code`(`recovery_code`);

CREATE INDEX `pa_recovery_code_user` ON `pa_recovery_code`(`user_id`);

CREATE UNIQUE INDEX `pa_recovery_code_puk` ON `pa_recovery_puk`(`recovery_code_id`, `puk_index`);
```

Migration script for PostgreSQL:
```sql
ALTER TABLE pa_activation_history ADD blocked_reason VARCHAR(255);
ALTER TABLE pa_activation_history ADD external_user_id VARCHAR(255);

CREATE SEQUENCE "pa_recovery_code_seq" MINVALUE 1 MAXVALUE 999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE "pa_recovery_puk_seq" MINVALUE 1 MAXVALUE 999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20;
CREATE SEQUENCE "pa_recovery_config_seq" MINVALUE 1 MAXVALUE 999999999999999999 INCREMENT BY 1 START WITH 1 CACHE 20;

--
-- DDL for Table PA_RECOVERY_CODE
--

CREATE TABLE "pa_recovery_code" (
    "id"                    INTEGER NOT NULL PRIMARY KEY,
    "recovery_code"         VARCHAR(23) NOT NULL,
    "application_id"        INTEGER NOT NULL,
    "user_id"               VARCHAR(255) NOT NULL,
    "activation_id"         VARCHAR(37),
    "status"                INTEGER NOT NULL,
    "failed_attempts"       INTEGER DEFAULT 0 NOT NULL,
    "max_failed_attempts"   INTEGER DEFAULT 10 NOT NULL,
    "timestamp_created"     TIMESTAMP (6) NOT NULL,
    "timestamp_last_used"   TIMESTAMP (6),
    "timestamp_last_change" TIMESTAMP (6)
);

--
-- DDL for Table PA_RECOVERY_PUK
--

CREATE TABLE "pa_recovery_puk" (
    "id"                    INTEGER NOT NULL PRIMARY KEY,
    "recovery_code_id"      INTEGER NOT NULL,
    "puk"                   VARCHAR(255),
    "puk_encryption"        INTEGER DEFAULT 0 NOT NULL,
    "puk_index"             INTEGER NOT NULL,
    "status"                INTEGER NOT NULL,
    "timestamp_last_change" TIMESTAMP (6)
);

--
-- DDL for Table PA_RECOVERY_CONFIG
--

CREATE TABLE "pa_recovery_config" (
    "id"                            NUMBER(19,0) NOT NULL PRIMARY KEY,
    "application_id"                NUMBER(19,0) NOT NULL,
    "activation_recovery_enabled"   BOOLEAN NOT NULL DEFAULT FALSE,
    "recovery_postcard_enabled"     BOOLEAN NOT NULL DEFAULT FALSE,
    "allow_multiple_recovery_codes" BOOLEAN NOT NULL DEFAULT FALSE,    
    "postcard_private_key_base64"   VARCHAR(255),
    "postcard_public_key_base64"    VARCHAR(255),
    "remote_public_key_base64"      VARCHAR(255)
);

--
--  Ref Constraints for Table PA_RECOVERY_CODE
--
ALTER TABLE "pa_recovery_code" ADD CONSTRAINT "recovery_code_application_fk" FOREIGN KEY ("application_id") REFERENCES "pa_application" ("id");
ALTER TABLE "pa_recovery_code" ADD CONSTRAINT "recovery_code_activation_fk" FOREIGN KEY ("activation_id") REFERENCES "pa_activation" ("activation_id");

--
--  Ref Constraints for Table PA_RECOVERY_PUK
--
ALTER TABLE "pa_recovery_puk" ADD CONSTRAINT "recovery_puk_code_fk" FOREIGN KEY ("recovery_code_id") REFERENCES "pa_recovery_code" ("id");

--
--  Ref Constraints for Table PA_RECOVERY_CONFIG
--
ALTER TABLE "pa_recovery_config" ADD CONSTRAINT "recovery_config_app_fk" FOREIGN KEY ("application_id") REFERENCES "pa_application" ("id");


CREATE INDEX PA_RECOVERY_CODE ON PA_RECOVERY_CODE(RECOVERY_CODE);

CREATE INDEX PA_RECOVERY_CODE_APP ON PA_RECOVERY_CODE(APPLICATION_ID);

CREATE INDEX PA_RECOVERY_CODE_USER ON PA_RECOVERY_CODE(USER_ID);

CREATE INDEX PA_RECOVERY_CODE_ACT ON PA_RECOVERY_CODE(ACTIVATION_ID);

CREATE UNIQUE INDEX PA_RECOVERY_CODE_PUK ON PA_RECOVERY_PUK(RECOVERY_CODE_ID, PUK_INDEX);

CREATE INDEX PA_RECOVERY_PUK_CODE ON PA_RECOVERY_PUK(RECOVERY_CODE_ID);
```

## SOAP Endpoint Changes

### WSDL Location Change

After [fixing the Spring bean naming conventions](https://github.com/wultra/powerauth-server/issues/285), the locations of the WSDL were changed.

**old** The original address:

- version 3: http://localhost:8080/powerauth-java-server/soap/service-v3.wsdl
- version 2: http://localhost:8080/powerauth-java-server/soap/service-v2.wsdl

**new** The current address:

- version 3: http://localhost:8080/powerauth-java-server/soap/serviceV3.wsdl
- version 2: http://localhost:8080/powerauth-java-server/soap/serviceV2.wsdl

### Offline Signatures and Biometry

The [VerifyOfflineSignature](./SOAP-Service-Methods.md#method-verifyofflinesignature) method has been updated to specify whether biometry is allowed in offline mode instead of specifying the used signature type directly. The PowerAuth client `verifyOfflineSignature` method has been updated to reflect the change of parameters. If you use offline mode verification using PowerAuth API, please update the SOAP method call.

### External User Identifier

The [CommitActivation](./SOAP-Service-Methods.md#method-commitactivation), [RemoveActivation](./SOAP-Service-Methods.md#method-removeactivation), [BlockActivation](./SOAP-Service-Methods.md#method-blockactivation) and [UnblockActivation](./SOAP-Service-Methods.md#method-unblockactivation) methods have been updated to allow specification of external user identifier. The related PowerAuth client methods have been updated to reflect the change of parameters. If you use any of these methods, please update the SOAP method call.

### Revoking Recovery Codes on Activation Removal

We added an optional `revokeRecoveryCodes` attribute to [activation removal service call](./SOAP-Service-Methods.md#method-removeactivation). This flag indicates if recovery codes that are associated with removed activation should be also revoked. By default, the value of the flag is `false`, hence omitting the flag results in the same behavior as before this change. 
