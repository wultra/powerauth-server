-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml
-- Ran at: 07/07/2026, 21:11
-- Against: null@offline:postgresql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::1::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_log (audit_log_id VARCHAR(36) NOT NULL, application_name VARCHAR(256) NOT NULL, audit_level VARCHAR(32) NOT NULL, audit_type VARCHAR(256), timestamp_created TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(), message TEXT NOT NULL, exception_message TEXT, stack_trace TEXT, param TEXT, calling_class VARCHAR(256) NOT NULL, thread_name VARCHAR(256) NOT NULL, version VARCHAR(256), build_time TIMESTAMP WITHOUT TIME ZONE, CONSTRAINT audit_log_pkey PRIMARY KEY (audit_log_id));

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::2::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_param (audit_log_id VARCHAR(36), timestamp_created TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(), param_key VARCHAR(256), param_value VARCHAR(4000));

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
CREATE SEQUENCE  IF NOT EXISTS pa_application_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::2::Lubos Racansky
-- Create a new sequence pa_application_version_seq
CREATE SEQUENCE  IF NOT EXISTS pa_application_version_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::3::Lubos Racansky
-- Create a new sequence pa_master_keypair_seq
CREATE SEQUENCE  IF NOT EXISTS pa_master_keypair_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::4::Lubos Racansky
-- Create a new sequence pa_signature_audit_seq
CREATE SEQUENCE  IF NOT EXISTS pa_signature_audit_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::5::Lubos Racansky
-- Create a new sequence pa_activation_history_seq
CREATE SEQUENCE  IF NOT EXISTS pa_activation_history_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::6::Lubos Racansky
-- Create a new sequence pa_recovery_code_seq
CREATE SEQUENCE  IF NOT EXISTS pa_recovery_code_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::7::Lubos Racansky
-- Create a new sequence pa_recovery_puk_seq
CREATE SEQUENCE  IF NOT EXISTS pa_recovery_puk_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::8::Lubos Racansky
-- Create a new sequence pa_recovery_config_seq
CREATE SEQUENCE  IF NOT EXISTS pa_recovery_config_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::9::Lubos Racansky
-- Create a new sequence pa_operation_template_seq
CREATE SEQUENCE  IF NOT EXISTS pa_operation_template_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::10::Lubos Racansky
-- Create a new table pa_application
CREATE TABLE pa_application (id INTEGER NOT NULL, name VARCHAR(255) NOT NULL, roles VARCHAR(255), CONSTRAINT pa_application_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::11::Lubos Racansky
-- Create a new table pa_master_keypair
CREATE TABLE pa_master_keypair (id INTEGER NOT NULL, application_id INTEGER NOT NULL, master_key_private_base64 VARCHAR(255) NOT NULL, master_key_public_base64 VARCHAR(255) NOT NULL, name VARCHAR(255), timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, CONSTRAINT pa_master_keypair_pkey PRIMARY KEY (id), CONSTRAINT keypair_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::12::Lubos Racansky
-- Create a new table pa_activation
CREATE TABLE pa_activation (activation_id VARCHAR(37) NOT NULL, application_id INTEGER NOT NULL, user_id VARCHAR(255) NOT NULL, activation_name VARCHAR(255), activation_code VARCHAR(255), activation_status INTEGER NOT NULL, activation_otp VARCHAR(255), activation_otp_validation INTEGER DEFAULT 0 NOT NULL, blocked_reason VARCHAR(255), counter INTEGER NOT NULL, ctr_data VARCHAR(255), device_public_key_base64 VARCHAR(255), extras VARCHAR(255), platform VARCHAR(255), device_info VARCHAR(255), flags VARCHAR(255), failed_attempts INTEGER NOT NULL, max_failed_attempts INTEGER DEFAULT 5 NOT NULL, server_private_key_base64 VARCHAR(255) NOT NULL, server_private_key_encryption INTEGER DEFAULT 0 NOT NULL, server_public_key_base64 VARCHAR(255) NOT NULL, timestamp_activation_expire TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, timestamp_last_used TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, timestamp_last_change TIMESTAMP(6) WITHOUT TIME ZONE, master_keypair_id INTEGER, version INTEGER DEFAULT 2, CONSTRAINT pa_activation_pkey PRIMARY KEY (activation_id), CONSTRAINT activation_keypair_fk FOREIGN KEY (master_keypair_id) REFERENCES pa_master_keypair(id), CONSTRAINT activation_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::13::Lubos Racansky
-- Create a new table pa_application_version
CREATE TABLE pa_application_version (id INTEGER NOT NULL, application_id INTEGER NOT NULL, application_key VARCHAR(255), application_secret VARCHAR(255), name VARCHAR(255), supported BOOLEAN, CONSTRAINT pa_application_version_pkey PRIMARY KEY (id), CONSTRAINT version_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::14::Lubos Racansky
-- Create a new table pa_signature_audit
CREATE TABLE pa_signature_audit (id BIGINT NOT NULL, activation_id VARCHAR(37) NOT NULL, activation_counter INTEGER NOT NULL, activation_ctr_data VARCHAR(255), activation_status INTEGER, additional_info VARCHAR(255), data_base64 TEXT, note VARCHAR(255), signature_type VARCHAR(255) NOT NULL, signature VARCHAR(255) NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, valid BOOLEAN, version INTEGER DEFAULT 2, signature_version VARCHAR(255), CONSTRAINT pa_signature_audit_pkey PRIMARY KEY (id), CONSTRAINT audit_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::15::Lubos Racansky
-- Create a new table pa_integration
CREATE TABLE pa_integration (id VARCHAR(37) NOT NULL, name VARCHAR(255), client_token VARCHAR(37) NOT NULL, client_secret VARCHAR(37) NOT NULL, CONSTRAINT pa_integration_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::16::Lubos Racansky
-- Create a new table pa_application_callback
CREATE TABLE pa_application_callback (id VARCHAR(37) NOT NULL, application_id INTEGER NOT NULL, name VARCHAR(255), callback_url VARCHAR(1024), type VARCHAR(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL, attributes VARCHAR(1024), authentication TEXT, CONSTRAINT pa_application_callback_pkey PRIMARY KEY (id), CONSTRAINT callback_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::17::Lubos Racansky
-- Create a new table pa_token
CREATE TABLE pa_token (token_id VARCHAR(37) NOT NULL, token_secret VARCHAR(255) NOT NULL, activation_id VARCHAR(37) NOT NULL, signature_type VARCHAR(255) NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, CONSTRAINT pa_token_pkey PRIMARY KEY (token_id), CONSTRAINT activation_token_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::18::Lubos Racansky
-- Create a new table pa_activation_history
CREATE TABLE pa_activation_history (id BIGINT NOT NULL, activation_id VARCHAR(37) NOT NULL, activation_status INTEGER, event_reason VARCHAR(255), external_user_id VARCHAR(255), timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, activation_version INTEGER, CONSTRAINT pa_activation_history_pkey PRIMARY KEY (id), CONSTRAINT history_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::19::Lubos Racansky
-- Create a new table pa_recovery_code
CREATE TABLE pa_recovery_code (id BIGINT NOT NULL, recovery_code VARCHAR(23) NOT NULL, application_id INTEGER NOT NULL, user_id VARCHAR(255) NOT NULL, activation_id VARCHAR(37), status INTEGER NOT NULL, failed_attempts INTEGER DEFAULT 0 NOT NULL, max_failed_attempts INTEGER DEFAULT 10 NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, timestamp_last_used TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_last_change TIMESTAMP(6) WITHOUT TIME ZONE, CONSTRAINT pa_recovery_code_pkey PRIMARY KEY (id), CONSTRAINT recovery_code_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT recovery_code_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::20::Lubos Racansky
-- Create a new table pa_recovery_puk
CREATE TABLE pa_recovery_puk (id BIGINT NOT NULL, recovery_code_id BIGINT NOT NULL, puk VARCHAR(255), puk_encryption INTEGER DEFAULT 0 NOT NULL, puk_index BIGINT NOT NULL, status INTEGER NOT NULL, timestamp_last_change TIMESTAMP(6) WITHOUT TIME ZONE, CONSTRAINT pa_recovery_puk_pkey PRIMARY KEY (id), CONSTRAINT recovery_puk_code_fk FOREIGN KEY (recovery_code_id) REFERENCES pa_recovery_code(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::21::Lubos Racansky
-- Create a new table pa_recovery_config
CREATE TABLE pa_recovery_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, activation_recovery_enabled BOOLEAN DEFAULT FALSE NOT NULL, recovery_postcard_enabled BOOLEAN DEFAULT FALSE NOT NULL, allow_multiple_recovery_codes BOOLEAN DEFAULT FALSE NOT NULL, postcard_private_key_base64 VARCHAR(255), postcard_public_key_base64 VARCHAR(255), remote_public_key_base64 VARCHAR(255), postcard_priv_key_encryption INTEGER DEFAULT 0 NOT NULL, CONSTRAINT pa_recovery_config_pkey PRIMARY KEY (id), CONSTRAINT recovery_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::22::Lubos Racansky
-- Create a new table pa_operation
CREATE TABLE pa_operation (id VARCHAR(37) NOT NULL, user_id VARCHAR(255) NOT NULL, external_id VARCHAR(255), activation_flag VARCHAR(255), operation_type VARCHAR(255) NOT NULL, template_name VARCHAR(255), data TEXT NOT NULL, parameters TEXT, additional_data TEXT, status INTEGER NOT NULL, signature_type VARCHAR(255) NOT NULL, failure_count BIGINT DEFAULT 0 NOT NULL, max_failure_count BIGINT NOT NULL, timestamp_created TIMESTAMP WITHOUT TIME ZONE NOT NULL, timestamp_expires TIMESTAMP WITHOUT TIME ZONE NOT NULL, timestamp_finalized TIMESTAMP WITHOUT TIME ZONE, risk_flags VARCHAR(255), CONSTRAINT pa_operation_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::23::Lubos Racansky
-- Create a new table pa_operation_template
CREATE TABLE pa_operation_template (id BIGINT NOT NULL, template_name VARCHAR(255) NOT NULL, operation_type VARCHAR(255) NOT NULL, data_template VARCHAR(255) NOT NULL, signature_type VARCHAR(255) NOT NULL, max_failure_count BIGINT NOT NULL, expiration BIGINT NOT NULL, risk_flags VARCHAR(255), CONSTRAINT pa_operation_template_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::24::Lubos Racansky
-- Create a new table pa_operation_application
CREATE TABLE pa_operation_application (application_id BIGINT NOT NULL, operation_id VARCHAR(37) NOT NULL, CONSTRAINT pa_operation_application_pkey PRIMARY KEY (application_id, operation_id));

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
CREATE TABLE shedlock (name VARCHAR(64) NOT NULL, lock_until TIMESTAMP WITHOUT TIME ZONE NOT NULL, locked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, locked_by VARCHAR(255) NOT NULL, CONSTRAINT shedlock_pkey PRIMARY KEY (name));

-- Changeset powerauth-java-server/1.4.x/20230323-add-tag-1.4.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.5.x/20230324-add-column-signature-data-body::1::Roman Strobl
-- Add signature_data_body column of type Clob
ALTER TABLE pa_signature_audit ADD signature_data_body TEXT;

-- Changeset powerauth-java-server/1.5.x/20230323-add-column-signature-metadata::1::Lubos Racansky
-- Add signature_metadata column of type Clob
ALTER TABLE pa_signature_audit ADD signature_metadata TEXT;

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::1::Lubos Racansky
-- Add totp_seed column
ALTER TABLE pa_operation ADD totp_seed VARCHAR(24);

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::2::Lubos Racansky
-- Add proximity_check_enabled column
ALTER TABLE pa_operation_template ADD proximity_check_enabled BOOLEAN DEFAULT FALSE NOT NULL;

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::1::Roman Strobl
-- Create a new table pa_unique_value
CREATE TABLE pa_unique_value (unique_value VARCHAR(255) NOT NULL, type INTEGER NOT NULL, timestamp_expires TIMESTAMP WITHOUT TIME ZONE NOT NULL, CONSTRAINT pa_unique_value_pkey PRIMARY KEY (unique_value));

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::2::Roman Strobl
-- Create a new index on pa_unique_value(timestamp_expires)
CREATE INDEX pa_unique_value_expiration ON pa_unique_value(timestamp_expires);

-- Changeset powerauth-java-server/1.5.x/20230822-add-tag-1.5.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.6.x/20231018-add-constraint-operation-template-name.xml::1::Jan Pesek
-- Add unique constraint to pa_operation_template.template_name
ALTER TABLE pa_operation_template ADD CONSTRAINT pa_operation_template_template_name_uk UNIQUE (template_name);

-- Changeset powerauth-java-server/1.6.x/20231103-add-activation-name-history.xml::1::Lubos Racansky
-- Add activation_name column to pa_activation_history
ALTER TABLE pa_activation_history ADD activation_name VARCHAR(255);

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::1::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application (id);

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::2::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_operation_id_fk FOREIGN KEY (operation_id) REFERENCES pa_operation (id);

-- Changeset powerauth-java-server/1.6.x/20231112-add-activation-id.xml::1::Jan Dusil
-- Add activation_id column to pa_operation with foreign key constraint
ALTER TABLE pa_operation ADD activation_id VARCHAR(37);

ALTER TABLE pa_operation ADD CONSTRAINT pa_operation_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation (activation_id);

-- Changeset powerauth-java-server/1.6.x/20231123-operation-user-nullable.xml::1::Roman Strobl
-- Make user_id column in table pa_operation nullable
ALTER TABLE pa_operation ALTER COLUMN  user_id DROP NOT NULL;

-- Changeset powerauth-java-server/1.6.x/20231212-add-tag-1.6.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id VARCHAR(255);

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol VARCHAR(32) DEFAULT 'powerauth';

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation ALTER COLUMN extras TYPE VARCHAR(4000) USING (extras::VARCHAR(4000));

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::4::Lubos Racansky
UPDATE pa_activation SET protocol = 'powerauth' WHERE protocol is null;

-- Changeset powerauth-java-server/1.7.x/20240530-protocol-not-null.xml::5::Lubos Racansky
-- Make column pa_activation.protocol not-null.
ALTER TABLE pa_activation ALTER COLUMN  protocol SET NOT NULL;

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id INTEGER NOT NULL, application_id INTEGER NOT NULL, config_key VARCHAR(255) NOT NULL, config_values TEXT, CONSTRAINT pa_application_config_pkey PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE INDEX pa_app_config_key_idx ON pa_application_config(config_key);

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE  IF NOT EXISTS pa_app_conf_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/1.7.x/20240312-fido2-authenticator.xml::1::Jan Pesek
-- Create a new table pa_fido2_authenticator
CREATE TABLE pa_fido2_authenticator (aaguid VARCHAR(255) NOT NULL, description VARCHAR(255) NOT NULL, signature_type VARCHAR(255) NOT NULL, CONSTRAINT pa_fido2_authenticator_pkey PRIMARY KEY (aaguid));

-- Changeset powerauth-java-server/1.7.x/20240222-add-tag-1.7.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp;

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);

-- Changeset powerauth-java-server/1.8.x/20240517-fido2-authenticator-transports.xml::1::Jan Pesek
-- Add transports column in pa_fido2_authenticator table.
ALTER TABLE pa_fido2_authenticator ADD transports VARCHAR(255);

-- Changeset powerauth-java-server/1.8.x/20240529-add-status-reason.xml::1::Lubos Racansky
-- Add status_reason column to pa_operation table.
ALTER TABLE pa_operation ADD status_reason VARCHAR(32);

-- Changeset powerauth-java-server/1.8.x/20240625-add-tag-1.8.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::1::Petr Dvorak
-- Create a new table pa_temporary_key
CREATE TABLE pa_temporary_key (id VARCHAR(37) NOT NULL, application_key VARCHAR(32) NOT NULL, activation_id VARCHAR(37), private_key_encryption INTEGER DEFAULT 0 NOT NULL, private_key_base64 VARCHAR(255) NOT NULL, public_key_base64 VARCHAR(255) NOT NULL, timestamp_expires TIMESTAMP WITHOUT TIME ZONE NOT NULL, CONSTRAINT pa_temporary_key_pkey PRIMARY KEY (id), CONSTRAINT pa_temporary_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::2::Petr Dvorak
-- Create a new index on pa_temporary_key(timestamp_expires)
CREATE INDEX pa_temporary_key_ts_key_idx ON pa_temporary_key(timestamp_expires);

-- Changeset powerauth-java-server/1.9.x/20240723-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_config table.
ALTER TABLE pa_application_config ADD encryption_mode VARCHAR(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240906-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD encryption_mode VARCHAR(255) DEFAULT 'NO_ENCRYPTION' NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20240910-commit-phase.xml::1::Roman Strobl
-- Add commit_phase column to pa_activation table.
ALTER TABLE pa_activation ADD commit_phase INTEGER DEFAULT 0;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_application_callback_event
CREATE TABLE pa_application_callback_event (id BIGINT NOT NULL, application_callback_id VARCHAR(37) NOT NULL, callback_data TEXT NOT NULL, status VARCHAR(32) NOT NULL, timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE DEFAULT NOW() NOT NULL, timestamp_last_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_next_call TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_delete_after TIMESTAMP(6) WITHOUT TIME ZONE, timestamp_rerun_after TIMESTAMP(6) WITHOUT TIME ZONE, attempts INTEGER DEFAULT 0 NOT NULL, idempotency_key VARCHAR(36) NOT NULL, CONSTRAINT pa_application_callback_event_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts INTEGER;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff VARCHAR(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period VARCHAR(64);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE INDEX pa_app_cb_event_status_idx ON pa_application_callback_event(status);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE INDEX pa_app_cb_event_ts_del_idx ON pa_application_callback_event(timestamp_delete_after);

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::7::Jan Pesek
-- Create a new sequence pa_app_callback_event_seq
CREATE SEQUENCE  IF NOT EXISTS pa_app_callback_event_seq START WITH 1 INCREMENT BY 50 CACHE 20;

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::10::Jan Pesek
-- Add enabled column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD enabled BOOLEAN DEFAULT TRUE NOT NULL;

-- Changeset powerauth-java-server/1.9.x/20241010-rest-client-caching.xml::1::Jan Pesek
-- Add columns timestamp_last_updated and timestamp_created to pa_application_callback table
ALTER TABLE pa_application_callback ADD timestamp_created TIMESTAMP(6) WITHOUT TIME ZONE DEFAULT NOW() NOT NULL;

ALTER TABLE pa_application_callback ADD timestamp_last_updated TIMESTAMP(6) WITHOUT TIME ZONE;

-- Changeset powerauth-java-server/1.9.x/20241003-add-tag-1.9.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.10.x/20250609-activation-additional-data.xml::1::Lubos Racansky
-- Add additional_data column to pa_activation table.
ALTER TABLE pa_activation ADD additional_data TEXT;

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm VARCHAR(32);

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD shared_secret VARCHAR(255);

ALTER TABLE pa_activation ADD shared_secret_encryption INTEGER DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys TEXT;

ALTER TABLE pa_master_keypair ADD master_private_keys_encryption INTEGER DEFAULT 0 NOT NULL;

ALTER TABLE pa_master_keypair ADD master_public_keys TEXT;

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 dynamic keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled BOOLEAN DEFAULT FALSE;

ALTER TABLE pa_activation ADD biometric_factor_key VARCHAR(255);

ALTER TABLE pa_activation ADD biometric_factor_key_next VARCHAR(255);

ALTER TABLE pa_activation ADD knowledge_factor_key VARCHAR(255);

ALTER TABLE pa_activation ADD knowledge_factor_key_next VARCHAR(255);

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::1::Roman Strobl
-- Add columns for crypto4 shared secret storage to pa_temporary_key table
ALTER TABLE pa_temporary_key ADD secret_key_base64 VARCHAR(255);

ALTER TABLE pa_temporary_key ADD secret_key_encryption INTEGER DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::2::Roman Strobl
-- Change the temporary keypair columns to nullable in pa_temporary_key table
ALTER TABLE pa_temporary_key ALTER COLUMN  private_key_base64 DROP NOT NULL;

ALTER TABLE pa_temporary_key ALTER COLUMN  public_key_base64 DROP NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20250709-crypto4-activation-confirmation.xml::1::Roman Strobl
-- Add column confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD confirmation_pending BOOLEAN DEFAULT FALSE;

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::1::Roman Strobl
-- Add column upgrade_confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD upgrade_confirmation_pending BOOLEAN DEFAULT FALSE;

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::2::Roman Strobl
-- Add column ctr_data_v4 to pa_activation table
ALTER TABLE pa_activation ADD ctr_data_v4 VARCHAR(255);

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::1::Lubos Racansky
-- Add column parent_activation_id to pa_activation table
ALTER TABLE pa_activation ADD parent_activation_id VARCHAR(37);

ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_parent_activation_id_fk FOREIGN KEY (parent_activation_id) REFERENCES pa_activation (activation_id);

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::2::Lubos Racansky
-- Add column transfer_type to pa_activation table
ALTER TABLE pa_activation ADD transfer_type VARCHAR(32);

-- Changeset powerauth-java-server/2.0.x/20251106-allow-null-legacy-keypairs.xml::1::Roman Strobl
-- Change the master keypair columns to nullable in pa_master_keypair table
ALTER TABLE pa_master_keypair ALTER COLUMN  master_key_private_base64 DROP NOT NULL;

ALTER TABLE pa_master_keypair ALTER COLUMN  master_key_public_base64 DROP NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::1::Jan Pesek
-- Change the server_private_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation ALTER COLUMN  server_private_key_base64 DROP NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::2::Jan Pesek
-- Change the server_public_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation ALTER COLUMN  server_public_key_base64 DROP NOT NULL;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::1::Jan Pesek
-- Create a new sequence pa_device_public_key_seq
CREATE SEQUENCE  IF NOT EXISTS pa_device_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::2::Jan Pesek
-- Create a new table pa_device_public_key
CREATE TABLE pa_device_public_key (id BIGINT DEFAULT nextval('pa_device_public_key_seq') NOT NULL, key_data TEXT, CONSTRAINT pa_device_public_key_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::3::Jan Pesek
-- Create a new sequence pa_server_public_key_seq
CREATE SEQUENCE  IF NOT EXISTS pa_server_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::4::Jan Pesek
-- Create a new table pa_server_public_key
CREATE TABLE pa_server_public_key (id BIGINT DEFAULT nextval('pa_server_public_key_seq') NOT NULL, key_data TEXT, CONSTRAINT pa_server_public_key_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::5::Jan Pesek
-- Create a new sequence pa_server_private_key_seq
CREATE SEQUENCE  IF NOT EXISTS pa_server_private_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::6::Jan Pesek
-- Create a new table pa_server_private_key
CREATE TABLE pa_server_private_key (id BIGINT DEFAULT nextval('pa_server_private_key_seq') NOT NULL, key_data TEXT, key_data_encryption INTEGER DEFAULT 0 NOT NULL, CONSTRAINT pa_server_private_key_pkey PRIMARY KEY (id));

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::7::Jan Pesek
-- Add new crypto4 key referencing columns to pa_activation table
ALTER TABLE pa_activation ADD device_public_key_id BIGINT;

ALTER TABLE pa_activation ADD CONSTRAINT pa_device_public_key_id_fk FOREIGN KEY (device_public_key_id) REFERENCES pa_device_public_key (id);

ALTER TABLE pa_activation ADD server_private_key_id BIGINT;

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_private_key_id_fk FOREIGN KEY (server_private_key_id) REFERENCES pa_server_private_key (id);

ALTER TABLE pa_activation ADD server_public_key_id BIGINT;

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_public_key_id_fk FOREIGN KEY (server_public_key_id) REFERENCES pa_server_public_key (id);

-- Changeset powerauth-java-server/2.0.x/20260107-crypto4-store-fingerprint.xml::1::Jan Pesek
-- Add column activation_fingerprint to pa_activation table
ALTER TABLE pa_activation ADD activation_fingerprint VARCHAR(255);

-- Changeset powerauth-java-server/2.0.x/20251215-add-tag-2.0.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-fix-nulls.xml::1::Vit Kotacka
-- Retrofit NULL activation_code values with unique LEGACY- prefixed placeholders
--             before adding the NOT NULL constraint. Skipped automatically (MARK_RAN) if no
--             NULL values are present, which is the expected case for all non-legacy databases.
--             Rollback is not supported — original NULL values cannot be restored.
UPDATE pa_activation
            SET activation_code = 'LEGACY-' || gen_random_uuid()::text
            WHERE activation_code IS NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::0::Vit Kotacka
-- MSSQL only: drop non-unique index pa_activation_code before ALTER COLUMN. MSSQL blocks ALTER COLUMN when a dependent index exists (error 5074); PostgreSQL and Oracle do not have this restriction.
DROP INDEX pa_activation_code;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Add NOT NULL constraint on pa_activation(activation_code) to align the DB schema with the JPA entity definition. Applied before the unique constraint to fail fast if NULL values exist, avoiding an expensive index build on dirty data.
ALTER TABLE pa_activation ALTER COLUMN  activation_code SET NOT NULL;

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (activation_code, application_id) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check. activation_code is NOT NULL (see changeset id=1), so multiple NULLs bypassing the unique constraint is not a concern.
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (activation_code, application_id);

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::3::Vit Kotacka
-- Safety-net drop of non-unique index pa_activation_code. Normally already dropped by id=0; this changeset is a no-op (MARK_RAN) on fresh installs but ensures correctness on environments that ran id=1..3 before id=0 was introduced.
DROP INDEX pa_activation_code;

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::1::Pavel Sindelar
-- Add subject_id column to audit_log table
ALTER TABLE audit_log ADD subject_id VARCHAR(256);

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::2::Pavel Sindelar
-- Create a new index on audit_log(subject_id)
CREATE INDEX audit_log_subject_id_idx ON audit_log(subject_id);

-- Changeset powerauth-java-server/2.1.x/20260416-add-tag-2.1.0.xml::1::Pavel Sindelar
-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store the signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format VARCHAR(32);

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Add signature_asymmetric CLOB column to pa_signature_audit table to store asymmetric signatures (ECDSA, ML-DSA)
ALTER TABLE pa_signature_audit ADD signature_asymmetric TEXT;

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::4::Roman Strobl
-- Rename signature column to auth_code in pa_signature_audit table to match the authentication code terminology
ALTER TABLE pa_signature_audit RENAME COLUMN signature TO auth_code;

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::5::Roman Strobl
-- Make auth_code column nullable in pa_signature_audit table because asymmetric audit records store their value in signature_asymmetric and leave auth_code null
ALTER TABLE pa_signature_audit ALTER COLUMN  auth_code DROP NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire TIMESTAMP(6) WITHOUT TIME ZONE;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count BIGINT DEFAULT 0 NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::3::Roman Strobl
-- Create a partial index on pa_activation(timestamp_block_expire) to support the scheduled expiration of temporary activation blocks (on Oracle a plain single-column index achieves the same effect, since all-null keys are not indexed)
CREATE INDEX pa_activation_block_expire_idx ON pa_activation(timestamp_block_expire) WHERE timestamp_block_expire IS NOT NULL;

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::1::Roman Strobl
-- Create a new table pa_config_store
CREATE TABLE pa_config_store (id BIGINT NOT NULL, application_id INTEGER NOT NULL, activation_id VARCHAR(37), config_scope VARCHAR(32) NOT NULL, config_data TEXT, encryption_mode VARCHAR(255) DEFAULT 'NO_ENCRYPTION' NOT NULL, timestamp_created TIMESTAMP WITHOUT TIME ZONE NOT NULL, timestamp_last_updated TIMESTAMP WITHOUT TIME ZONE, CONSTRAINT pa_config_store_pkey PRIMARY KEY (id), CONSTRAINT pa_config_store_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT pa_config_store_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::2::Roman Strobl
-- Create a new sequence pa_config_store_seq
CREATE SEQUENCE  IF NOT EXISTS pa_config_store_seq START WITH 1 INCREMENT BY 50 CACHE 20;

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::3::Roman Strobl
-- Create a new index on pa_config_store(application_id)
CREATE INDEX pa_config_store_application_id_idx ON pa_config_store(application_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::4::Roman Strobl
-- Create a new index on pa_config_store(activation_id)
CREATE INDEX pa_config_store_activation_id_idx ON pa_config_store(activation_id);

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::5::Roman Strobl
-- Create a unique index on pa_config_store(application_id, activation_id, config_scope).
CREATE UNIQUE INDEX pa_config_store_application_id_activation_id_config_scope_idx ON pa_config_store(application_id, activation_id, config_scope);

