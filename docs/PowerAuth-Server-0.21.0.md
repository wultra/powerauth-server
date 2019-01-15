---
layout: page
title: Migration from 0.19.0 to 0.21.0
---

This guide contains instructions for migration from PowerAuth Server version 0.19.0 to version 0.21.0.

## Database Changes

Following DB changes occurred between version 0.19.0 and 0.21.0:
- Table `PA_ACTIVATION` - added columns `CTR_DATA` and `VERSION` for support of PowerAuth protocol version 3.0
- Table `PA_ACTIVATION` - column `ACTIVATION_CODE` replaces `ACTIVATION_ID_SHORT` and `ACTIVATION_OTP` in PowerAuth protocol version 3.0
- Table `PA_SIGNATURE_AUDIT` - added columns `ACTIVATION_CTR_DATA` and `VERSION` for support of PowerAuth protocol version 3.0

Migration script for Oracle:
```
--
--  Added Column ACTIVATION_CODE in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD ACTIVATION_CODE VARCHAR2(255 CHAR);

--
--  Added Column CTR_DATA in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD CTR_DATA VARCHAR2(255 CHAR);

--
--  Added Column VERSION in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD VERSION NUMBER(2,0) DEFAULT 2;

--
--  Added Column ACTIVATION_CTR_DATA in Table PA_SIGNATURE_AUDIT
--
ALTER TABLE PA_SIGNATURE_AUDIT ADD ACTIVATION_CTR_DATA VARCHAR2(255 CHAR);

--
--  Added Column VERSION in Table PA_SIGNATURE_AUDIT
--
ALTER TABLE PA_SIGNATURE_AUDIT ADD VERSION NUMBER(2,0) DEFAULT 2;

--
--  Column ACTIVATION_CODE Filled with Data from ACTIVATION_ID_SHORT || '-' || ACTIATION_OTP
--
UPDATE PA_ACTIVATION SET ACTIVATION_CODE = ACTIVATION_ID_SHORT || '-' || ACTIVATION_OTP;

--
--  Dropped Column ACTIVATION_ID_SHORT in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION DROP COLUMN ACTIVATION_ID_SHORT;

--
--  Dropped Column ACTIVATION_OTP in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION DROP COLUMN ACTIVATION_OTP;
```

Migration script for MySQL:
```
--
--  Added Column ACTIVATION_CODE in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD ACTIVATION_CODE VARCHAR(255);

--
--  Added Column CTR_DATA in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD CTR_DATA VARCHAR(255);

--
--  Added Column VERSION in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION ADD VERSION INT(2) DEFAULT 2;

--
--  Added Column ACTIVATION_CTR_DATA in Table PA_SIGNATURE_AUDIT
--
ALTER TABLE PA_SIGNATURE_AUDIT ADD ACTIVATION_CTR_DATA VARCHAR(255);

--
--  Added Column VERSION in Table PA_SIGNATURE_AUDIT
--
ALTER TABLE PA_SIGNATURE_AUDIT ADD VERSION INT(2) DEFAULT 2;

--
--  Column ACTIVATION_CODE Filled with Data from ACTIVATION_ID_SHORT || '-' || ACTIATION_OTP
--
UPDATE PA_ACTIVATION SET ACTIVATION_CODE = ACTIVATION_ID_SHORT || '-' || ACTIVATION_OTP;

--
--  Dropped Column ACTIVATION_ID_SHORT in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION DROP COLUMN ACTIVATION_ID_SHORT;

--
--  Dropped Column ACTIVATION_OTP in Table PA_ACTIVATION
--
ALTER TABLE PA_ACTIVATION DROP COLUMN ACTIVATION_OTP;
```

## Database Indexes

We have added database indexes into the official DDL scripts. In case you already added your own indexes to PowerAuth, please check that all required indexes are present. Otherwise you can add all of the indexes using provided SQL script.

Index definition which was tested on Oracle, MySQL and PostgreSQL:
```
CREATE INDEX PA_ACTIVATION_CODE ON PA_ACTIVATION(ACTIVATION_CODE);

CREATE INDEX PA_ACTIVATION_USER_ID ON PA_ACTIVATION(USER_ID);

CREATE INDEX PA_ACTIVATION_HISTORY_CREATED ON PA_ACTIVATION_HISTORY(TIMESTAMP_CREATED);

CREATE UNIQUE INDEX PA_APP_VERSION_APP_KEY ON PA_APPLICATION_VERSION(APPLICATION_KEY);

CREATE INDEX PA_APP_CALLBACK_APP ON PA_APPLICATION_CALLBACK(APPLICATION_ID);

CREATE UNIQUE INDEX PA_INTEGRATION_TOKEN ON PA_INTEGRATION(CLIENT_TOKEN);

CREATE INDEX PA_SIGNATURE_AUDIT_CREATED ON PA_SIGNATURE_AUDIT(TIMESTAMP_CREATED);
```

### Activation Short ID Change to Activation Code

The setting `generateActivationShortIdIterations` in PowerAuth server `application.properties` configuration has been replaced by `generateActivationCodeIterations`. In case you do not customize this setting, you can safely ignore this change.

The `UNABLE_TO_GENERATE_SHORT_ACTIVATION_ID` error code has been changed to `UNABLE_TO_GENERATE_ACTIVATION_CODE`. In case you do not process the PowerAuth server error codes, you can safely ignore this change.