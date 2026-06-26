-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml
-- Ran at: 5/18/26, 1:17 PM
-- Against: null@offline:oracle
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::1::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_log (audit_log_id VARCHAR2(36) NOT NULL, application_name VARCHAR2(256) NOT NULL, audit_level VARCHAR2(32) NOT NULL, audit_type VARCHAR2(256), timestamp_created TIMESTAMP DEFAULT sysdate, message CLOB NOT NULL, exception_message CLOB, stack_trace CLOB, param CLOB, calling_class VARCHAR2(256) NOT NULL, thread_name VARCHAR2(256) NOT NULL, version VARCHAR2(256), build_time TIMESTAMP, CONSTRAINT PK_AUDIT_LOG PRIMARY KEY (audit_log_id));

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::2::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_param (audit_log_id VARCHAR2(36), timestamp_created TIMESTAMP DEFAULT sysdate, param_key VARCHAR2(256), param_value VARCHAR2(4000));

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::3::Lubos Racansky
-- Create a new index on audit_log(timestamp_created)
CREATE INDEX audit_log_timestamp ON audit_log(timestamp_created);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::4::Lubos Racansky
-- Create a new index on audit_log(application_name)
CREATE INDEX audit_log_application ON audit_log(application_name);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::5::Lubos Racansky
-- Create a new index on audit_log(audit_level)
CREATE INDEX audit_log_level ON audit_log(audit_level);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::6::Lubos Racansky
-- Create a new index on audit_log(audit_type)
CREATE INDEX audit_log_type ON audit_log(audit_type);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::7::Lubos Racansky
-- Create a new index on audit_param(audit_log_id)
CREATE INDEX audit_param_log ON audit_param(audit_log_id);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::8::Lubos Racansky
-- Create a new index on audit_param(timestamp_created)
CREATE INDEX audit_param_timestamp ON audit_param(timestamp_created);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::9::Lubos Racansky
-- Create a new index on audit_log(param_key)
CREATE INDEX audit_param_key ON audit_param(param_key);

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::10::Lubos Racansky
-- Create a new index on audit_log(param_value)
CREATE INDEX audit_param_value ON audit_param(param_value);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::1::Lubos Racansky
-- Create a new sequence pa_application_seq
CREATE SEQUENCE pa_application_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::2::Lubos Racansky
-- Create a new sequence pa_application_version_seq
CREATE SEQUENCE pa_application_version_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::3::Lubos Racansky
-- Create a new sequence pa_master_keypair_seq
CREATE SEQUENCE pa_master_keypair_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::4::Lubos Racansky
-- Create a new sequence pa_signature_audit_seq
CREATE SEQUENCE pa_signature_audit_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::5::Lubos Racansky
-- Create a new sequence pa_activation_history_seq
CREATE SEQUENCE pa_activation_history_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::6::Lubos Racansky
-- Create a new sequence pa_recovery_code_seq
CREATE SEQUENCE pa_recovery_code_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::7::Lubos Racansky
-- Create a new sequence pa_recovery_puk_seq
CREATE SEQUENCE pa_recovery_puk_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::8::Lubos Racansky
-- Create a new sequence pa_recovery_config_seq
CREATE SEQUENCE pa_recovery_config_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::9::Lubos Racansky
-- Create a new sequence pa_operation_template_seq
CREATE SEQUENCE pa_operation_template_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::10::Lubos Racansky
-- Create a new table pa_application
CREATE TABLE pa_application (id INTEGER NOT NULL, name VARCHAR2(255) NOT NULL, roles VARCHAR2(255), CONSTRAINT PK_PA_APPLICATION PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::11::Lubos Racansky
-- Create a new table pa_master_keypair
CREATE TABLE pa_master_keypair (id INTEGER NOT NULL, application_id INTEGER NOT NULL, master_key_private_base64 VARCHAR2(255) NOT NULL, master_key_public_base64 VARCHAR2(255) NOT NULL, name VARCHAR2(255), timestamp_created TIMESTAMP(6) NOT NULL, CONSTRAINT PK_PA_MASTER_KEYPAIR PRIMARY KEY (id), CONSTRAINT keypair_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::12::Lubos Racansky
-- Create a new table pa_activation
CREATE TABLE pa_activation (activation_id VARCHAR2(37) NOT NULL, application_id INTEGER NOT NULL, user_id VARCHAR2(255) NOT NULL, activation_name VARCHAR2(255), activation_code VARCHAR2(255), activation_status INTEGER NOT NULL, activation_otp VARCHAR2(255), activation_otp_validation INTEGER DEFAULT 0 NOT NULL, blocked_reason VARCHAR2(255), counter INTEGER NOT NULL, ctr_data VARCHAR2(255), device_public_key_base64 VARCHAR2(255), extras VARCHAR2(255), platform VARCHAR2(255), device_info VARCHAR2(255), flags VARCHAR2(255), failed_attempts INTEGER NOT NULL, max_failed_attempts INTEGER DEFAULT 5 NOT NULL, server_private_key_base64 VARCHAR2(255) NOT NULL, server_private_key_encryption INTEGER DEFAULT 0 NOT NULL, server_public_key_base64 VARCHAR2(255) NOT NULL, timestamp_activation_expire TIMESTAMP(6) NOT NULL, timestamp_created TIMESTAMP(6) NOT NULL, timestamp_last_used TIMESTAMP(6) NOT NULL, timestamp_last_change TIMESTAMP(6), master_keypair_id INTEGER, version INTEGER DEFAULT 2, CONSTRAINT PK_PA_ACTIVATION PRIMARY KEY (activation_id), CONSTRAINT activation_keypair_fk FOREIGN KEY (master_keypair_id) REFERENCES pa_master_keypair(id), CONSTRAINT activation_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::13::Lubos Racansky
-- Create a new table pa_application_version
CREATE TABLE pa_application_version (id INTEGER NOT NULL, application_id INTEGER NOT NULL, application_key VARCHAR2(255), application_secret VARCHAR2(255), name VARCHAR2(255), supported BOOLEAN, CONSTRAINT PK_PA_APPLICATION_VERSION PRIMARY KEY (id), CONSTRAINT version_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::14::Lubos Racansky
-- Create a new table pa_signature_audit
CREATE TABLE pa_signature_audit (id NUMBER(38, 0) NOT NULL, activation_id VARCHAR2(37) NOT NULL, activation_counter INTEGER NOT NULL, activation_ctr_data VARCHAR2(255), activation_status INTEGER, additional_info VARCHAR2(255), data_base64 CLOB, note VARCHAR2(255), signature_type VARCHAR2(255) NOT NULL, signature VARCHAR2(255) NOT NULL, timestamp_created TIMESTAMP(6) NOT NULL, valid BOOLEAN, version INTEGER DEFAULT 2, signature_version VARCHAR2(255), CONSTRAINT PK_PA_SIGNATURE_AUDIT PRIMARY KEY (id), CONSTRAINT audit_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::15::Lubos Racansky
-- Create a new table pa_integration
CREATE TABLE pa_integration (id VARCHAR2(37) NOT NULL, name VARCHAR2(255), client_token VARCHAR2(37) NOT NULL, client_secret VARCHAR2(37) NOT NULL, CONSTRAINT PK_PA_INTEGRATION PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::16::Lubos Racansky
-- Create a new table pa_application_callback
CREATE TABLE pa_application_callback (id VARCHAR2(37) NOT NULL, application_id INTEGER NOT NULL, name VARCHAR2(255), callback_url VARCHAR2(1024), type VARCHAR2(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL, attributes VARCHAR2(1024), authentication CLOB, CONSTRAINT PK_PA_APPLICATION_CALLBACK PRIMARY KEY (id), CONSTRAINT callback_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::17::Lubos Racansky
-- Create a new table pa_token
CREATE TABLE pa_token (token_id VARCHAR2(37) NOT NULL, token_secret VARCHAR2(255) NOT NULL, activation_id VARCHAR2(37) NOT NULL, signature_type VARCHAR2(255) NOT NULL, timestamp_created TIMESTAMP(6) NOT NULL, CONSTRAINT PK_PA_TOKEN PRIMARY KEY (token_id), CONSTRAINT activation_token_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::18::Lubos Racansky
-- Create a new table pa_activation_history
CREATE TABLE pa_activation_history (id NUMBER(38, 0) NOT NULL, activation_id VARCHAR2(37) NOT NULL, activation_status INTEGER, event_reason VARCHAR2(255), external_user_id VARCHAR2(255), timestamp_created TIMESTAMP(6) NOT NULL, activation_version INTEGER, CONSTRAINT PK_PA_ACTIVATION_HISTORY PRIMARY KEY (id), CONSTRAINT history_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::19::Lubos Racansky
-- Create a new table pa_recovery_code
CREATE TABLE pa_recovery_code (id NUMBER(38, 0) NOT NULL, recovery_code VARCHAR2(23) NOT NULL, application_id INTEGER NOT NULL, user_id VARCHAR2(255) NOT NULL, activation_id VARCHAR2(37), status INTEGER NOT NULL, failed_attempts INTEGER DEFAULT 0 NOT NULL, max_failed_attempts INTEGER DEFAULT 10 NOT NULL, timestamp_created TIMESTAMP(6) NOT NULL, timestamp_last_used TIMESTAMP(6), timestamp_last_change TIMESTAMP(6), CONSTRAINT PK_PA_RECOVERY_CODE PRIMARY KEY (id), CONSTRAINT recovery_code_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT recovery_code_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::20::Lubos Racansky
-- Create a new table pa_recovery_puk
CREATE TABLE pa_recovery_puk (id NUMBER(38, 0) NOT NULL, recovery_code_id NUMBER(38, 0) NOT NULL, puk VARCHAR2(255), puk_encryption INTEGER DEFAULT 0 NOT NULL, puk_index NUMBER(38, 0) NOT NULL, status INTEGER NOT NULL, timestamp_last_change TIMESTAMP(6), CONSTRAINT PK_PA_RECOVERY_PUK PRIMARY KEY (id), CONSTRAINT recovery_puk_code_fk FOREIGN KEY (recovery_code_id) REFERENCES pa_recovery_code(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::21::Lubos Racansky
-- Create a new table pa_recovery_config
CREATE TABLE pa_recovery_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, activation_recovery_enabled BOOLEAN DEFAULT 0 NOT NULL, recovery_postcard_enabled BOOLEAN DEFAULT 0 NOT NULL, allow_multiple_recovery_codes BOOLEAN DEFAULT 0 NOT NULL, postcard_private_key_base64 VARCHAR2(255), postcard_public_key_base64 VARCHAR2(255), remote_public_key_base64 VARCHAR2(255), postcard_priv_key_encryption INTEGER DEFAULT 0 NOT NULL, CONSTRAINT PK_PA_RECOVERY_CONFIG PRIMARY KEY (id), CONSTRAINT recovery_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::22::Lubos Racansky
-- Create a new table pa_operation
CREATE TABLE pa_operation (id VARCHAR2(37) NOT NULL, user_id VARCHAR2(255) NOT NULL, external_id VARCHAR2(255), activation_flag VARCHAR2(255), operation_type VARCHAR2(255) NOT NULL, template_name VARCHAR2(255), data CLOB NOT NULL, parameters CLOB, additional_data CLOB, status INTEGER NOT NULL, signature_type VARCHAR2(255) NOT NULL, failure_count NUMBER(38, 0) DEFAULT 0 NOT NULL, max_failure_count NUMBER(38, 0) NOT NULL, timestamp_created TIMESTAMP NOT NULL, timestamp_expires TIMESTAMP NOT NULL, timestamp_finalized TIMESTAMP, risk_flags VARCHAR2(255), CONSTRAINT PK_PA_OPERATION PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::23::Lubos Racansky
-- Create a new table pa_operation_template
CREATE TABLE pa_operation_template (id NUMBER(38, 0) NOT NULL, template_name VARCHAR2(255) NOT NULL, operation_type VARCHAR2(255) NOT NULL, data_template VARCHAR2(255) NOT NULL, signature_type VARCHAR2(255) NOT NULL, max_failure_count NUMBER(38, 0) NOT NULL, expiration NUMBER(38, 0) NOT NULL, risk_flags VARCHAR2(255), CONSTRAINT PK_PA_OPERATION_TEMPLATE PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::24::Lubos Racansky
-- Create a new table pa_operation_application
CREATE TABLE pa_operation_application (application_id NUMBER(38, 0) NOT NULL, operation_id VARCHAR2(37) NOT NULL, CONSTRAINT PK_PA_OPERATION_APPLICATION PRIMARY KEY (application_id, operation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::26::Lubos Racansky
-- Create a new index on pa_activation(application_id)
CREATE INDEX pa_activation_application ON pa_activation(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::27::Lubos Racansky
-- Create a new index on pa_activation(master_keypair_id)
CREATE INDEX pa_activation_keypair ON pa_activation(master_keypair_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::28::Lubos Racansky
-- Create a new index on pa_activation(activation_code)
CREATE INDEX pa_activation_code ON pa_activation(activation_code);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::29::Lubos Racansky
-- Create a new index on pa_activation(user_id)
CREATE INDEX pa_activation_user_id ON pa_activation(user_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::30::Lubos Racansky
-- Create a new index on pa_activation(activation_status, timestamp_activation_expire)
CREATE INDEX pa_activation_expiration ON pa_activation(activation_status, timestamp_activation_expire);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::31::Lubos Racansky
-- Create a new index on pa_activation_history(activation_id)
CREATE INDEX pa_activation_history_act ON pa_activation_history(activation_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::32::Lubos Racansky
-- Create a new index on pa_activation_history(timestamp_created)
CREATE INDEX pa_activation_history_created ON pa_activation_history(timestamp_created);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::33::Lubos Racansky
-- Create a new index on pa_application_version(application_id)
CREATE INDEX pa_application_version_app ON pa_application_version(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::34::Lubos Racansky
-- Create a new index on pa_master_keypair(application_id)
CREATE INDEX pa_master_keypair_application ON pa_master_keypair(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::35::Lubos Racansky
-- Create a new unique index on pa_application_version(application_key)
CREATE UNIQUE INDEX pa_app_version_app_key ON pa_application_version(application_key);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::36::Lubos Racansky
-- Create a new index on pa_application_callback(application_id)
CREATE INDEX pa_app_callback_app ON pa_application_callback(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::37::Lubos Racansky
-- Create a new unique index on pa_integration(client_token)
CREATE UNIQUE INDEX pa_integration_token ON pa_integration(client_token);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::38::Lubos Racansky
-- Create a new index on pa_signature_audit(activation_id)
CREATE INDEX pa_signature_audit_activation ON pa_signature_audit(activation_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::39::Lubos Racansky
-- Create a new index on pa_signature_audit(timestamp_created)
CREATE INDEX pa_signature_audit_created ON pa_signature_audit(timestamp_created);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::40::Lubos Racansky
-- Create a new index on pa_token(activation_id)
CREATE INDEX pa_token_activation ON pa_token(activation_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::41::Lubos Racansky
-- Create a new index on pa_recovery_code(recovery_code)
CREATE INDEX pa_recovery_code_code ON pa_recovery_code(recovery_code);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::42::Lubos Racansky
-- Create a new index on pa_recovery_code(application_id)
CREATE INDEX pa_recovery_code_app ON pa_recovery_code(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::43::Lubos Racansky
-- Create a new index on pa_recovery_code(user_id)
CREATE INDEX pa_recovery_code_user ON pa_recovery_code(user_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::44::Lubos Racansky
-- Create a new index on pa_recovery_code(activation_id)
CREATE INDEX pa_recovery_code_act ON pa_recovery_code(activation_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::45::Lubos Racansky
-- Create a new unique index on pa_recovery_puk(recovery_code_id, puk_index)
CREATE UNIQUE INDEX pa_recovery_code_puk ON pa_recovery_puk(recovery_code_id, puk_index);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::46::Lubos Racansky
-- Create a new index on pa_recovery_puk(recovery_code_id)
CREATE INDEX pa_recovery_puk_code ON pa_recovery_puk(recovery_code_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::47::Lubos Racansky
-- Create a new unique index on pa_recovery_config(application_id)
CREATE UNIQUE INDEX pa_recovery_config_app ON pa_recovery_config(application_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::48::Lubos Racansky
-- Create a new unique index on pa_application(name)
CREATE UNIQUE INDEX pa_application_name ON pa_application(name);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::49::Lubos Racansky
-- Create a new index on pa_operation(user_id)
CREATE INDEX pa_operation_user ON pa_operation(user_id);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::50::Lubos Racansky
-- Create a new index on pa_operation(timestamp_created)
CREATE INDEX pa_operation_ts_created_idx ON pa_operation(timestamp_created);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::51::Lubos Racansky
-- Create a new index on pa_operation(timestamp_expires)
CREATE INDEX pa_operation_ts_expires_idx ON pa_operation(timestamp_expires);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::52::Lubos Racansky
-- Create a new index on pa_operation(timestamp_expires, status)
CREATE INDEX pa_operation_status_exp ON pa_operation(timestamp_expires, status);

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::53::Lubos Racansky
-- Create a new index on pa_operation_template(template_name)
CREATE INDEX pa_operation_template_name_idx ON pa_operation_template(template_name);

-- Changeset powerauth-java-server/1.4.x/20230322-shedlock.xml::1::Lubos Racansky
-- Create a new table shedlock
CREATE TABLE shedlock (name VARCHAR2(64) NOT NULL, lock_until TIMESTAMP NOT NULL, locked_at TIMESTAMP NOT NULL, locked_by VARCHAR2(255) NOT NULL, CONSTRAINT PK_SHEDLOCK PRIMARY KEY (name));

-- Changeset powerauth-java-server/1.4.x/20230323-add-tag-1.4.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.5.x/20230324-add-column-signature-data-body::1::Roman Strobl
-- Add signature_data_body column of type Clob
ALTER TABLE pa_signature_audit ADD signature_data_body CLOB;

-- Changeset powerauth-java-server/1.5.x/20230323-add-column-signature-metadata::1::Lubos Racansky
-- Add signature_metadata column of type Clob
ALTER TABLE pa_signature_audit ADD signature_metadata CLOB;

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::1::Lubos Racansky
-- Add totp_seed column
ALTER TABLE pa_operation ADD totp_seed VARCHAR2(24);

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::2::Lubos Racansky
-- Add proximity_check_enabled column
ALTER TABLE pa_operation_template ADD proximity_check_enabled BOOLEAN DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::1::Roman Strobl
-- Create a new table pa_unique_value
CREATE TABLE pa_unique_value (unique_value VARCHAR2(255) NOT NULL, type INTEGER NOT NULL, timestamp_expires TIMESTAMP NOT NULL, CONSTRAINT PK_PA_UNIQUE_VALUE PRIMARY KEY (unique_value));

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::2::Roman Strobl
-- Create a new index on pa_unique_value(timestamp_expires)
CREATE INDEX pa_unique_value_expiration ON pa_unique_value(timestamp_expires);

-- Changeset powerauth-java-server/1.5.x/20230822-add-tag-1.5.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.6.x/20231018-add-constraint-operation-template-name.xml::1::Jan Pesek
-- Add unique constraint to pa_operation_template.template_name
ALTER TABLE pa_operation_template ADD CONSTRAINT pa_operation_template_template_name_uk UNIQUE (template_name);

-- Changeset powerauth-java-server/1.6.x/20231103-add-activation-name-history.xml::1::Lubos Racansky
-- Add activation_name column to pa_activation_history
ALTER TABLE pa_activation_history ADD activation_name VARCHAR2(255);

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::1::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application (id);

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::2::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_operation_id_fk FOREIGN KEY (operation_id) REFERENCES pa_operation (id);

-- Changeset powerauth-java-server/1.6.x/20231112-add-activation-id.xml::1::Jan Dusil
-- Add activation_id column to pa_operation with foreign key constraint
ALTER TABLE pa_operation ADD activation_id VARCHAR2(37);

ALTER TABLE pa_operation ADD CONSTRAINT pa_operation_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation (activation_id);

-- Changeset powerauth-java-server/1.6.x/20231123-operation-user-nullable.xml::1::Roman Strobl
-- Make user_id column in table pa_operation nullable
ALTER TABLE pa_operation MODIFY user_id NULL;

-- Changeset powerauth-java-server/1.6.x/20231212-add-tag-1.6.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id VARCHAR2(255);

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol VARCHAR2(32) DEFAULT 'powerauth';

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation MODIFY extras VARCHAR2(4000);

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::4::Lubos Racansky
UPDATE pa_activation SET protocol = 'powerauth' WHERE protocol is null;

-- Changeset powerauth-java-server/1.7.x/20240530-protocol-not-null.xml::5::Lubos Racansky
-- Make column pa_activation.protocol not-null.
ALTER TABLE pa_activation MODIFY protocol NOT NULL;

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, config_key VARCHAR2(255) NOT NULL, config_values CLOB, CONSTRAINT PK_PA_APPLICATION_CONFIG PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE INDEX pa_app_config_key_idx ON pa_application_config(config_key);

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE pa_app_conf_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.7.x/20240312-fido2-authenticator.xml::1::Jan Pesek
-- Create a new table pa_fido2_authenticator
CREATE TABLE pa_fido2_authenticator (aaguid VARCHAR2(255) NOT NULL, description VARCHAR2(255) NOT NULL, signature_type VARCHAR2(255) NOT NULL, CONSTRAINT PK_PA_FIDO2_AUTHENTICATOR PRIMARY KEY (aaguid));

-- Changeset powerauth-java-server/1.7.x/20240222-add-tag-1.7.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp;

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);

-- Changeset powerauth-java-server/1.8.x/20240517-fido2-authenticator-transports.xml::1::Jan Pesek
-- Add transports column in pa_fido2_authenticator table.
ALTER TABLE pa_fido2_authenticator ADD transports VARCHAR2(255);

-- Changeset powerauth-java-server/1.8.x/20240529-add-status-reason.xml::1::Lubos Racansky
-- Add status_reason column to pa_operation table.
ALTER TABLE pa_operation ADD status_reason VARCHAR2(32);

-- Changeset powerauth-java-server/1.8.x/20240625-add-tag-1.8.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::1::Petr Dvorak
-- Create a new table pa_temporary_key
CREATE TABLE pa_temporary_key (id VARCHAR2(37) NOT NULL, application_key VARCHAR2(32) NOT NULL, activation_id VARCHAR2(37), private_key_encryption INTEGER DEFAULT 0 NOT NULL, private_key_base64 VARCHAR2(255) NOT NULL, public_key_base64 VARCHAR2(255) NOT NULL, timestamp_expires TIMESTAMP NOT NULL, CONSTRAINT PK_PA_TEMPORARY_KEY PRIMARY KEY (id), CONSTRAINT pa_temporary_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::2::Petr Dvorak
-- Create a new index on pa_temporary_key(timestamp_expires)
CREATE INDEX pa_temporary_key_ts_key_idx ON pa_temporary_key(timestamp_expires);

-- Changeset powerauth-java-server/1.9.x/20240723-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_config table.
ALTER TABLE pa_application_config ADD encryption_mode VARCHAR2(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240906-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD encryption_mode VARCHAR2(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240910-commit-phase.xml::1::Roman Strobl
-- Add commit_phase column to pa_activation table.
ALTER TABLE pa_activation ADD commit_phase INTEGER DEFAULT '0';

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_application_callback_event
CREATE TABLE pa_application_callback_event (id NUMBER(38, 0) NOT NULL, application_callback_id VARCHAR2(37) NOT NULL, callback_data CLOB NOT NULL, status VARCHAR2(32) NOT NULL, timestamp_created TIMESTAMP(6) DEFAULT sysdate NOT NULL, timestamp_last_call TIMESTAMP(6), timestamp_next_call TIMESTAMP(6), timestamp_delete_after TIMESTAMP(6), timestamp_rerun_after TIMESTAMP(6), attempts INTEGER DEFAULT 0 NOT NULL, idempotency_key VARCHAR2(36) NOT NULL, CONSTRAINT PK_PA_APPLICATION_CALLBACK_EVENT PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts INTEGER;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff VARCHAR2(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period VARCHAR2(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE INDEX pa_app_cb_event_status_idx ON pa_application_callback_event(status);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE INDEX pa_app_cb_event_ts_del_idx ON pa_application_callback_event(timestamp_delete_after);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::7::Jan Pesek
-- Create a new sequence pa_app_callback_event_seq
CREATE SEQUENCE pa_app_callback_event_seq START WITH 1 INCREMENT BY 50 CACHE 20;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::10::Jan Pesek
-- Add enabled column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD enabled BOOLEAN DEFAULT 1 NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20241010-rest-client-caching.xml::1::Jan Pesek
-- Add columns timestamp_last_updated and timestamp_created to pa_application_callback table
ALTER TABLE pa_application_callback ADD timestamp_created TIMESTAMP(6) DEFAULT sysdate NOT NULL;

ALTER TABLE pa_application_callback ADD timestamp_last_updated TIMESTAMP(6);

-- Changeset powerauth-java-server/1.9.x/20241003-add-tag-1.9.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.10.x/20250609-activation-additional-data.xml::1::Lubos Racansky
-- Add additional_data column to pa_activation table.
ALTER TABLE pa_activation ADD additional_data CLOB;

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm VARCHAR2(32);

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD shared_secret VARCHAR2(255);

ALTER TABLE pa_activation ADD shared_secret_encryption INTEGER DEFAULT '0' NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys CLOB;

ALTER TABLE pa_master_keypair ADD master_private_keys_encryption INTEGER DEFAULT '0' NOT NULL;

ALTER TABLE pa_master_keypair ADD master_public_keys CLOB;

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 dynamic keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled BOOLEAN DEFAULT 0;

ALTER TABLE pa_activation ADD biometric_factor_key VARCHAR2(255);

ALTER TABLE pa_activation ADD biometric_factor_key_next VARCHAR2(255);

ALTER TABLE pa_activation ADD knowledge_factor_key VARCHAR2(255);

ALTER TABLE pa_activation ADD knowledge_factor_key_next VARCHAR2(255);

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::1::Roman Strobl
-- Add columns for crypto4 shared secret storage to pa_temporary_key table
ALTER TABLE pa_temporary_key ADD secret_key_base64 VARCHAR2(255);

ALTER TABLE pa_temporary_key ADD secret_key_encryption INTEGER DEFAULT '0' NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::2::Roman Strobl
-- Change the temporary keypair columns to nullable in pa_temporary_key table
ALTER TABLE pa_temporary_key MODIFY private_key_base64 NULL;

ALTER TABLE pa_temporary_key MODIFY public_key_base64 NULL;

-- Changeset powerauth-java-server/2.0.x/20250709-crypto4-activation-confirmation.xml::1::Roman Strobl
-- Add column confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD confirmation_pending BOOLEAN DEFAULT 0;

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::1::Roman Strobl
-- Add column upgrade_confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD upgrade_confirmation_pending BOOLEAN DEFAULT 0;

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::2::Roman Strobl
-- Add column ctr_data_v4 to pa_activation table
ALTER TABLE pa_activation ADD ctr_data_v4 VARCHAR2(255);

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::1::Lubos Racansky
-- Add column parent_activation_id to pa_activation table
ALTER TABLE pa_activation ADD parent_activation_id VARCHAR2(37);

ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_parent_activation_id_fk FOREIGN KEY (parent_activation_id) REFERENCES pa_activation (activation_id);

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::2::Lubos Racansky
-- Add column transfer_type to pa_activation table
ALTER TABLE pa_activation ADD transfer_type VARCHAR2(32);

-- Changeset powerauth-java-server/2.0.x/20251106-allow-null-legacy-keypairs.xml::1::Roman Strobl
-- Change the master keypair columns to nullable in pa_master_keypair table
ALTER TABLE pa_master_keypair MODIFY master_key_private_base64 NULL;

ALTER TABLE pa_master_keypair MODIFY master_key_public_base64 NULL;

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::1::Jan Pesek
-- Change the server_private_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation MODIFY server_private_key_base64 NULL;

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::2::Jan Pesek
-- Change the server_public_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation MODIFY server_public_key_base64 NULL;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::1::Jan Pesek
-- Create a new sequence pa_device_public_key_seq
CREATE SEQUENCE pa_device_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::2::Jan Pesek
-- Create a new table pa_device_public_key
CREATE TABLE pa_device_public_key (id NUMBER(38, 0) DEFAULT pa_device_public_key_seq.nextval NOT NULL, key_data CLOB, CONSTRAINT PK_PA_DEVICE_PUBLIC_KEY PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::3::Jan Pesek
-- Create a new sequence pa_server_public_key_seq
CREATE SEQUENCE pa_server_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::4::Jan Pesek
-- Create a new table pa_server_public_key
CREATE TABLE pa_server_public_key (id NUMBER(38, 0) DEFAULT pa_server_public_key_seq.nextval NOT NULL, key_data CLOB, CONSTRAINT PK_PA_SERVER_PUBLIC_KEY PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::5::Jan Pesek
-- Create a new sequence pa_server_private_key_seq
CREATE SEQUENCE pa_server_private_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::6::Jan Pesek
-- Create a new table pa_server_private_key
CREATE TABLE pa_server_private_key (id NUMBER(38, 0) DEFAULT pa_server_private_key_seq.nextval NOT NULL, key_data CLOB, key_data_encryption INTEGER DEFAULT 0 NOT NULL, CONSTRAINT PK_PA_SERVER_PRIVATE_KEY PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::7::Jan Pesek
-- Add new crypto4 key referencing columns to pa_activation table
ALTER TABLE pa_activation ADD device_public_key_id NUMBER(38, 0);

ALTER TABLE pa_activation ADD CONSTRAINT pa_device_public_key_id_fk FOREIGN KEY (device_public_key_id) REFERENCES pa_device_public_key (id);

ALTER TABLE pa_activation ADD server_private_key_id NUMBER(38, 0);

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_private_key_id_fk FOREIGN KEY (server_private_key_id) REFERENCES pa_server_private_key (id);

ALTER TABLE pa_activation ADD server_public_key_id NUMBER(38, 0);

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_public_key_id_fk FOREIGN KEY (server_public_key_id) REFERENCES pa_server_public_key (id);

-- Changeset powerauth-java-server/2.0.x/20260107-crypto4-store-fingerprint.xml::1::Jan Pesek
-- Add column activation_fingerprint to pa_activation table
ALTER TABLE pa_activation ADD activation_fingerprint VARCHAR2(255);

-- Changeset powerauth-java-server/2.0.x/20251215-add-tag-2.0.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-fix-nulls.xml::1::Vit Kotacka
-- Retrofit NULL activation_code values with unique LEGACY- prefixed placeholders
--             before adding the NOT NULL constraint. Skipped automatically (MARK_RAN) if no
--             NULL values are present, which is the expected case for all non-legacy databases.
--             Rollback is not supported — original NULL values cannot be restored.
UPDATE pa_activation
SET activation_code = 'LEGACY-' || LOWER(RAWTOHEX(SYS_GUID()))
WHERE activation_code IS NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::0::Vit Kotacka
-- MSSQL only: drop non-unique index pa_activation_code before ALTER COLUMN. MSSQL blocks ALTER COLUMN when a dependent index exists (error 5074); PostgreSQL and Oracle do not have this restriction.
DROP INDEX pa_activation_code;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Add NOT NULL constraint on pa_activation(activation_code) to align the DB schema with the JPA entity definition. Applied before the unique constraint to fail fast if NULL values exist, avoiding an expensive index build on dirty data.
ALTER TABLE pa_activation MODIFY activation_code NOT NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (activation_code, application_id) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check. activation_code is NOT NULL (see changeset id=1), so multiple NULLs bypassing the unique constraint is not a concern.
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (activation_code, application_id);

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::3::Vit Kotacka
-- Safety-net drop of non-unique index pa_activation_code. Normally already dropped by id=0; this changeset is a no-op (MARK_RAN) on fresh installs but ensures correctness on environments that ran id=1..3 before id=0 was introduced.
DROP INDEX pa_activation_code;

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::1::Pavel Sindelar
-- Add subject_id column to audit_log table
ALTER TABLE audit_log ADD subject_id VARCHAR2(256);

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::2::Pavel Sindelar
-- Create a new index on audit_log(subject_id)
CREATE INDEX audit_log_subject_id_idx ON audit_log(subject_id);

-- Changeset powerauth-java-server/2.1.x/20260416-add-tag-2.1.0.xml::1::Pavel Sindelar
-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm VARCHAR2(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format VARCHAR2(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Change data type of signature column in pa_signature_audit table from varchar(255) to text to support longer asymmetric signatures
ALTER TABLE pa_signature_audit MODIFY signature CLOB;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire TIMESTAMP(6);

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count NUMBER(38, 0) DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::3::Roman Strobl
-- Create a partial index on pa_activation(timestamp_block_expire) to support the scheduled expiration of temporary activation blocks (on Oracle a plain single-column index achieves the same effect, since all-null keys are not indexed)
CREATE INDEX pa_activation_block_expire_idx ON pa_activation(timestamp_block_expire);


-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::1::Roman Strobl
-- Create a new table pa_config_store
CREATE TABLE pa_config_store (id NUMBER(38, 0) NOT NULL, application_id INTEGER NOT NULL, activation_id VARCHAR2(37), config_scope VARCHAR2(32) NOT NULL, config_data CLOB, encryption_mode VARCHAR2(255) DEFAULT 'NO_ENCRYPTION' NOT NULL, timestamp_created TIMESTAMP(6) NOT NULL, timestamp_last_updated TIMESTAMP(6), CONSTRAINT PK_PA_CONFIG_STORE PRIMARY KEY (id), CONSTRAINT pa_config_store_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT pa_config_store_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::2::Roman Strobl
-- Create a new sequence pa_config_store_seq
CREATE SEQUENCE pa_config_store_seq START WITH 1 INCREMENT BY 50 CACHE 20;

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::3::Roman Strobl
-- Create a new index on pa_config_store(application_id)
CREATE INDEX pa_config_store_application_id_idx ON pa_config_store(application_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::4::Roman Strobl
-- Create a new index on pa_config_store(activation_id)
CREATE INDEX pa_config_store_activation_id_idx ON pa_config_store(activation_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::5::Roman Strobl
-- Create a unique index on pa_config_store(application_id, activation_id, config_scope).
CREATE UNIQUE INDEX pa_config_store_application_id_activation_id_config_scope_idx ON pa_config_store(application_id, activation_id, config_scope);
