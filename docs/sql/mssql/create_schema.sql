-- *********************************************************************
-- Update Database Script
-- *********************************************************************
-- Change Log: ./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml
-- Ran at: 5/18/26, 1:18 PM
-- Against: null@offline:mssql
-- Liquibase version: 4.33.0
-- *********************************************************************

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::1::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_log (audit_log_id varchar(36) NOT NULL, application_name varchar(256) NOT NULL, audit_level varchar(32) NOT NULL, audit_type varchar(256), timestamp_created datetime2 CONSTRAINT DF_audit_log_timestamp_created DEFAULT GETDATE(), message varchar (max) NOT NULL, exception_message varchar (max), stack_trace varchar (max), param varchar (max), calling_class varchar(256) NOT NULL, thread_name varchar(256) NOT NULL, version varchar(256), build_time datetime2, CONSTRAINT PK_AUDIT_LOG PRIMARY KEY (audit_log_id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::2::Lubos Racansky
-- Create a new table audit_log
CREATE TABLE audit_param (audit_log_id varchar(36), timestamp_created datetime2 CONSTRAINT DF_audit_param_timestamp_created DEFAULT GETDATE(), param_key varchar(256), param_value varchar(4000));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::3::Lubos Racansky
-- Create a new index on audit_log(timestamp_created)
CREATE NONCLUSTERED INDEX audit_log_timestamp ON audit_log(timestamp_created);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::4::Lubos Racansky
-- Create a new index on audit_log(application_name)
CREATE NONCLUSTERED INDEX audit_log_application ON audit_log(application_name);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::5::Lubos Racansky
-- Create a new index on audit_log(audit_level)
CREATE NONCLUSTERED INDEX audit_log_level ON audit_log(audit_level);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::6::Lubos Racansky
-- Create a new index on audit_log(audit_type)
CREATE NONCLUSTERED INDEX audit_log_type ON audit_log(audit_type);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::7::Lubos Racansky
-- Create a new index on audit_param(audit_log_id)
CREATE NONCLUSTERED INDEX audit_param_log ON audit_param(audit_log_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::8::Lubos Racansky
-- Create a new index on audit_param(timestamp_created)
CREATE NONCLUSTERED INDEX audit_param_timestamp ON audit_param(timestamp_created);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::9::Lubos Racansky
-- Create a new index on audit_log(param_key)
CREATE NONCLUSTERED INDEX audit_param_key ON audit_param(param_key);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-audit.xml::10::Lubos Racansky
-- Create a new index on audit_log(param_value)
CREATE NONCLUSTERED INDEX audit_param_value ON audit_param(param_value);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::1::Lubos Racansky
-- Create a new sequence pa_application_seq
CREATE SEQUENCE pa_application_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::2::Lubos Racansky
-- Create a new sequence pa_application_version_seq
CREATE SEQUENCE pa_application_version_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::3::Lubos Racansky
-- Create a new sequence pa_master_keypair_seq
CREATE SEQUENCE pa_master_keypair_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::4::Lubos Racansky
-- Create a new sequence pa_signature_audit_seq
CREATE SEQUENCE pa_signature_audit_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::5::Lubos Racansky
-- Create a new sequence pa_activation_history_seq
CREATE SEQUENCE pa_activation_history_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::6::Lubos Racansky
-- Create a new sequence pa_recovery_code_seq
CREATE SEQUENCE pa_recovery_code_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::7::Lubos Racansky
-- Create a new sequence pa_recovery_puk_seq
CREATE SEQUENCE pa_recovery_puk_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::8::Lubos Racansky
-- Create a new sequence pa_recovery_config_seq
CREATE SEQUENCE pa_recovery_config_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::9::Lubos Racansky
-- Create a new sequence pa_operation_template_seq
CREATE SEQUENCE pa_operation_template_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::10::Lubos Racansky
-- Create a new table pa_application
CREATE TABLE pa_application (id int NOT NULL, name varchar(255) NOT NULL, roles varchar(255), CONSTRAINT PK_PA_APPLICATION PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::11::Lubos Racansky
-- Create a new table pa_master_keypair
CREATE TABLE pa_master_keypair (id int NOT NULL, application_id int NOT NULL, master_key_private_base64 varchar(255) NOT NULL, master_key_public_base64 varchar(255) NOT NULL, name varchar(255), timestamp_created datetime2(6) NOT NULL, CONSTRAINT PK_PA_MASTER_KEYPAIR PRIMARY KEY (id), CONSTRAINT keypair_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::12::Lubos Racansky
-- Create a new table pa_activation
CREATE TABLE pa_activation (activation_id varchar(37) NOT NULL, application_id int NOT NULL, user_id varchar(255) NOT NULL, activation_name varchar(255), activation_code varchar(255), activation_status int NOT NULL, activation_otp varchar(255), activation_otp_validation int CONSTRAINT DF_pa_activation_activation_otp_validation DEFAULT 0 NOT NULL, blocked_reason varchar(255), counter int NOT NULL, ctr_data varchar(255), device_public_key_base64 varchar(255), extras varchar(255), platform varchar(255), device_info varchar(255), flags varchar(255), failed_attempts int NOT NULL, max_failed_attempts int CONSTRAINT DF_pa_activation_max_failed_attempts DEFAULT 5 NOT NULL, server_private_key_base64 varchar(255) NOT NULL, server_private_key_encryption int CONSTRAINT DF_pa_activation_server_private_key_encryption DEFAULT 0 NOT NULL, server_public_key_base64 varchar(255) NOT NULL, timestamp_activation_expire datetime2(6) NOT NULL, timestamp_created datetime2(6) NOT NULL, timestamp_last_used datetime2(6) NOT NULL, timestamp_last_change datetime2(6), master_keypair_id int, version int CONSTRAINT DF_pa_activation_version DEFAULT 2, CONSTRAINT PK_PA_ACTIVATION PRIMARY KEY (activation_id), CONSTRAINT activation_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT activation_keypair_fk FOREIGN KEY (master_keypair_id) REFERENCES pa_master_keypair(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::13::Lubos Racansky
-- Create a new table pa_application_version
CREATE TABLE pa_application_version (id int NOT NULL, application_id int NOT NULL, application_key varchar(255), application_secret varchar(255), name varchar(255), supported bit, CONSTRAINT PK_PA_APPLICATION_VERSION PRIMARY KEY (id), CONSTRAINT version_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::14::Lubos Racansky
-- Create a new table pa_signature_audit
CREATE TABLE pa_signature_audit (id bigint NOT NULL, activation_id varchar(37) NOT NULL, activation_counter int NOT NULL, activation_ctr_data varchar(255), activation_status int, additional_info varchar(255), data_base64 varchar (max), note varchar(255), signature_type varchar(255) NOT NULL, signature varchar(255) NOT NULL, timestamp_created datetime2(6) NOT NULL, valid bit, version int CONSTRAINT DF_pa_signature_audit_version DEFAULT 2, signature_version varchar(255), CONSTRAINT PK_PA_SIGNATURE_AUDIT PRIMARY KEY (id), CONSTRAINT audit_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::15::Lubos Racansky
-- Create a new table pa_integration
CREATE TABLE pa_integration (id varchar(37) NOT NULL, name varchar(255), client_token varchar(37) NOT NULL, client_secret varchar(37) NOT NULL, CONSTRAINT PK_PA_INTEGRATION PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::16::Lubos Racansky
-- Create a new table pa_application_callback
CREATE TABLE pa_application_callback (id varchar(37) NOT NULL, application_id int NOT NULL, name varchar(255), callback_url varchar(1024), type varchar(64) CONSTRAINT DF_pa_application_callback_type DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL, attributes varchar(1024), authentication varchar (max), CONSTRAINT PK_PA_APPLICATION_CALLBACK PRIMARY KEY (id), CONSTRAINT callback_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::17::Lubos Racansky
-- Create a new table pa_token
CREATE TABLE pa_token (token_id varchar(37) NOT NULL, token_secret varchar(255) NOT NULL, activation_id varchar(37) NOT NULL, signature_type varchar(255) NOT NULL, timestamp_created datetime2(6) NOT NULL, CONSTRAINT PK_PA_TOKEN PRIMARY KEY (token_id), CONSTRAINT activation_token_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::18::Lubos Racansky
-- Create a new table pa_activation_history
CREATE TABLE pa_activation_history (id bigint NOT NULL, activation_id varchar(37) NOT NULL, activation_status int, event_reason varchar(255), external_user_id varchar(255), timestamp_created datetime2(6) NOT NULL, activation_version int, CONSTRAINT PK_PA_ACTIVATION_HISTORY PRIMARY KEY (id), CONSTRAINT history_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::19::Lubos Racansky
-- Create a new table pa_recovery_code
CREATE TABLE pa_recovery_code (id bigint NOT NULL, recovery_code varchar(23) NOT NULL, application_id int NOT NULL, user_id varchar(255) NOT NULL, activation_id varchar(37), status int NOT NULL, failed_attempts int CONSTRAINT DF_pa_recovery_code_failed_attempts DEFAULT 0 NOT NULL, max_failed_attempts int CONSTRAINT DF_pa_recovery_code_max_failed_attempts DEFAULT 10 NOT NULL, timestamp_created datetime2(6) NOT NULL, timestamp_last_used datetime2(6), timestamp_last_change datetime2(6), CONSTRAINT PK_PA_RECOVERY_CODE PRIMARY KEY (id), CONSTRAINT recovery_code_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id), CONSTRAINT recovery_code_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::20::Lubos Racansky
-- Create a new table pa_recovery_puk
CREATE TABLE pa_recovery_puk (id bigint NOT NULL, recovery_code_id bigint NOT NULL, puk varchar(255), puk_encryption int CONSTRAINT DF_pa_recovery_puk_puk_encryption DEFAULT 0 NOT NULL, puk_index bigint NOT NULL, status int NOT NULL, timestamp_last_change datetime2(6), CONSTRAINT PK_PA_RECOVERY_PUK PRIMARY KEY (id), CONSTRAINT recovery_puk_code_fk FOREIGN KEY (recovery_code_id) REFERENCES pa_recovery_code(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::21::Lubos Racansky
-- Create a new table pa_recovery_config
CREATE TABLE pa_recovery_config (id int NOT NULL, application_id int NOT NULL, activation_recovery_enabled bit CONSTRAINT DF_pa_recovery_config_activation_recovery_enabled DEFAULT 0 NOT NULL, recovery_postcard_enabled bit CONSTRAINT DF_pa_recovery_config_recovery_postcard_enabled DEFAULT 0 NOT NULL, allow_multiple_recovery_codes bit CONSTRAINT DF_pa_recovery_config_allow_multiple_recovery_codes DEFAULT 0 NOT NULL, postcard_private_key_base64 varchar(255), postcard_public_key_base64 varchar(255), remote_public_key_base64 varchar(255), postcard_priv_key_encryption int CONSTRAINT DF_pa_recovery_config_postcard_priv_key_encryption DEFAULT 0 NOT NULL, CONSTRAINT PK_PA_RECOVERY_CONFIG PRIMARY KEY (id), CONSTRAINT recovery_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::22::Lubos Racansky
-- Create a new table pa_operation
CREATE TABLE pa_operation (id varchar(37) NOT NULL, user_id varchar(255) NOT NULL, external_id varchar(255), activation_flag varchar(255), operation_type varchar(255) NOT NULL, template_name varchar(255), data varchar (max) NOT NULL, parameters varchar (max), additional_data varchar (max), status int NOT NULL, signature_type varchar(255) NOT NULL, failure_count bigint CONSTRAINT DF_pa_operation_failure_count DEFAULT 0 NOT NULL, max_failure_count bigint NOT NULL, timestamp_created datetime2 NOT NULL, timestamp_expires datetime2 NOT NULL, timestamp_finalized datetime2, risk_flags varchar(255), CONSTRAINT PK_PA_OPERATION PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::23::Lubos Racansky
-- Create a new table pa_operation_template
CREATE TABLE pa_operation_template (id bigint NOT NULL, template_name varchar(255) NOT NULL, operation_type varchar(255) NOT NULL, data_template varchar(255) NOT NULL, signature_type varchar(255) NOT NULL, max_failure_count bigint NOT NULL, expiration bigint NOT NULL, risk_flags varchar(255), CONSTRAINT PK_PA_OPERATION_TEMPLATE PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::24::Lubos Racansky
-- Create a new table pa_operation_application
CREATE TABLE pa_operation_application (application_id bigint NOT NULL, operation_id varchar(37) NOT NULL, CONSTRAINT PK_PA_OPERATION_APPLICATION PRIMARY KEY (application_id, operation_id));
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::26::Lubos Racansky
-- Create a new index on pa_activation(application_id)
CREATE NONCLUSTERED INDEX pa_activation_application ON pa_activation(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::27::Lubos Racansky
-- Create a new index on pa_activation(master_keypair_id)
CREATE NONCLUSTERED INDEX pa_activation_keypair ON pa_activation(master_keypair_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::28::Lubos Racansky
-- Create a new index on pa_activation(activation_code)
CREATE NONCLUSTERED INDEX pa_activation_code ON pa_activation(activation_code);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::29::Lubos Racansky
-- Create a new index on pa_activation(user_id)
CREATE NONCLUSTERED INDEX pa_activation_user_id ON pa_activation(user_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::30::Lubos Racansky
-- Create a new index on pa_activation(activation_status, timestamp_activation_expire)
CREATE NONCLUSTERED INDEX pa_activation_expiration ON pa_activation(activation_status, timestamp_activation_expire);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::31::Lubos Racansky
-- Create a new index on pa_activation_history(activation_id)
CREATE NONCLUSTERED INDEX pa_activation_history_act ON pa_activation_history(activation_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::32::Lubos Racansky
-- Create a new index on pa_activation_history(timestamp_created)
CREATE NONCLUSTERED INDEX pa_activation_history_created ON pa_activation_history(timestamp_created);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::33::Lubos Racansky
-- Create a new index on pa_application_version(application_id)
CREATE NONCLUSTERED INDEX pa_application_version_app ON pa_application_version(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::34::Lubos Racansky
-- Create a new index on pa_master_keypair(application_id)
CREATE NONCLUSTERED INDEX pa_master_keypair_application ON pa_master_keypair(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::35::Lubos Racansky
-- Create a new unique index on pa_application_version(application_key)
CREATE UNIQUE NONCLUSTERED INDEX pa_app_version_app_key ON pa_application_version(application_key);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::36::Lubos Racansky
-- Create a new index on pa_application_callback(application_id)
CREATE NONCLUSTERED INDEX pa_app_callback_app ON pa_application_callback(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::37::Lubos Racansky
-- Create a new unique index on pa_integration(client_token)
CREATE UNIQUE NONCLUSTERED INDEX pa_integration_token ON pa_integration(client_token);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::38::Lubos Racansky
-- Create a new index on pa_signature_audit(activation_id)
CREATE NONCLUSTERED INDEX pa_signature_audit_activation ON pa_signature_audit(activation_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::39::Lubos Racansky
-- Create a new index on pa_signature_audit(timestamp_created)
CREATE NONCLUSTERED INDEX pa_signature_audit_created ON pa_signature_audit(timestamp_created);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::40::Lubos Racansky
-- Create a new index on pa_token(activation_id)
CREATE NONCLUSTERED INDEX pa_token_activation ON pa_token(activation_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::41::Lubos Racansky
-- Create a new index on pa_recovery_code(recovery_code)
CREATE NONCLUSTERED INDEX pa_recovery_code_code ON pa_recovery_code(recovery_code);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::42::Lubos Racansky
-- Create a new index on pa_recovery_code(application_id)
CREATE NONCLUSTERED INDEX pa_recovery_code_app ON pa_recovery_code(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::43::Lubos Racansky
-- Create a new index on pa_recovery_code(user_id)
CREATE NONCLUSTERED INDEX pa_recovery_code_user ON pa_recovery_code(user_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::44::Lubos Racansky
-- Create a new index on pa_recovery_code(activation_id)
CREATE NONCLUSTERED INDEX pa_recovery_code_act ON pa_recovery_code(activation_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::45::Lubos Racansky
-- Create a new unique index on pa_recovery_puk(recovery_code_id, puk_index)
CREATE UNIQUE NONCLUSTERED INDEX pa_recovery_code_puk ON pa_recovery_puk(recovery_code_id, puk_index);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::46::Lubos Racansky
-- Create a new index on pa_recovery_puk(recovery_code_id)
CREATE NONCLUSTERED INDEX pa_recovery_puk_code ON pa_recovery_puk(recovery_code_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::47::Lubos Racansky
-- Create a new unique index on pa_recovery_config(application_id)
CREATE UNIQUE NONCLUSTERED INDEX pa_recovery_config_app ON pa_recovery_config(application_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::48::Lubos Racansky
-- Create a new unique index on pa_application(name)
CREATE UNIQUE NONCLUSTERED INDEX pa_application_name ON pa_application(name);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::49::Lubos Racansky
-- Create a new index on pa_operation(user_id)
CREATE NONCLUSTERED INDEX pa_operation_user ON pa_operation(user_id);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::50::Lubos Racansky
-- Create a new index on pa_operation(timestamp_created)
CREATE NONCLUSTERED INDEX pa_operation_ts_created_idx ON pa_operation(timestamp_created);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::51::Lubos Racansky
-- Create a new index on pa_operation(timestamp_expires)
CREATE NONCLUSTERED INDEX pa_operation_ts_expires_idx ON pa_operation(timestamp_expires);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::52::Lubos Racansky
-- Create a new index on pa_operation(timestamp_expires, status)
CREATE NONCLUSTERED INDEX pa_operation_status_exp ON pa_operation(timestamp_expires, status);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::53::Lubos Racansky
-- Create a new index on pa_operation_template(template_name)
CREATE NONCLUSTERED INDEX pa_operation_template_name_idx ON pa_operation_template(template_name);
GO

-- Changeset powerauth-java-server/1.4.x/20230322-shedlock.xml::1::Lubos Racansky
-- Create a new table shedlock
CREATE TABLE shedlock (name varchar(64) NOT NULL, lock_until datetime2 NOT NULL, locked_at datetime2 NOT NULL, locked_by varchar(255) NOT NULL, CONSTRAINT PK_SHEDLOCK PRIMARY KEY (name));
GO

-- Changeset powerauth-java-server/1.4.x/20230323-add-tag-1.4.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.5.x/20230324-add-column-signature-data-body::1::Roman Strobl
-- Add signature_data_body column of type Clob
ALTER TABLE pa_signature_audit ADD signature_data_body varchar(MAX);
GO

-- Changeset powerauth-java-server/1.5.x/20230323-add-column-signature-metadata::1::Lubos Racansky
-- Add signature_metadata column of type Clob
ALTER TABLE pa_signature_audit ADD signature_metadata varchar(MAX);
GO

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::1::Lubos Racansky
-- Add totp_seed column
ALTER TABLE pa_operation ADD totp_seed varchar(24);
GO

-- Changeset powerauth-java-server/1.5.x/20230426-add-column-totp-seed::2::Lubos Racansky
-- Add proximity_check_enabled column
ALTER TABLE pa_operation_template ADD proximity_check_enabled bit CONSTRAINT DF_pa_operation_template_proximity_check_enabled DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::1::Roman Strobl
-- Create a new table pa_unique_value
CREATE TABLE pa_unique_value (unique_value varchar(255) NOT NULL, type int NOT NULL, timestamp_expires datetime2 NOT NULL, CONSTRAINT PK_PA_UNIQUE_VALUE PRIMARY KEY (unique_value));
GO

-- Changeset powerauth-java-server/1.5.x/20230723-add-table-unique-value.xml::2::Roman Strobl
-- Create a new index on pa_unique_value(timestamp_expires)
CREATE NONCLUSTERED INDEX pa_unique_value_expiration ON pa_unique_value(timestamp_expires);
GO

-- Changeset powerauth-java-server/1.5.x/20230822-add-tag-1.5.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.6.x/20231018-add-constraint-operation-template-name.xml::1::Jan Pesek
-- Add unique constraint to pa_operation_template.template_name
ALTER TABLE pa_operation_template ADD CONSTRAINT pa_operation_template_template_name_uk UNIQUE (template_name);
GO

-- Changeset powerauth-java-server/1.6.x/20231103-add-activation-name-history.xml::1::Lubos Racansky
-- Add activation_name column to pa_activation_history
ALTER TABLE pa_activation_history ADD activation_name varchar(255);
GO

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::1::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application (id);
GO

-- Changeset powerauth-java-server/1.6.x/20231106-add-foreign-keys.xml::2::Jan Pesek
ALTER TABLE pa_operation_application ADD CONSTRAINT pa_operation_application_operation_id_fk FOREIGN KEY (operation_id) REFERENCES pa_operation (id);
GO

-- Changeset powerauth-java-server/1.6.x/20231112-add-activation-id.xml::1::Jan Dusil
-- Add activation_id column to pa_operation with foreign key constraint
ALTER TABLE pa_operation ADD activation_id varchar(37);
GO

ALTER TABLE pa_operation ADD CONSTRAINT pa_operation_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation (activation_id);
GO

-- Changeset powerauth-java-server/1.6.x/20231123-operation-user-nullable.xml::1::Roman Strobl
-- Make user_id column in table pa_operation nullable
ALTER TABLE pa_operation ALTER COLUMN user_id varchar(255) NULL;
GO

-- Changeset powerauth-java-server/1.6.x/20231212-add-tag-1.6.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::1::Roman Strobl
-- Add external_id column
ALTER TABLE pa_activation ADD external_id varchar(255);
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::2::Roman Strobl
-- Add protocol column
ALTER TABLE pa_activation ADD protocol varchar(32) CONSTRAINT DF_pa_activation_protocol DEFAULT 'powerauth';
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::3::Roman Strobl
ALTER TABLE pa_activation ALTER COLUMN extras varchar(4000);
GO

-- Changeset powerauth-java-server/1.7.x/20240115-add-columns-fido2::4::Lubos Racansky
UPDATE pa_activation SET protocol = 'powerauth' WHERE protocol is null;
GO

-- Changeset powerauth-java-server/1.7.x/20240530-protocol-not-null.xml::5::Lubos Racansky
-- Make column pa_activation.protocol not-null.
ALTER TABLE pa_activation ALTER COLUMN protocol varchar(32) NOT NULL;
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::1::Roman Strobl
-- Create a new table pa_application_config
CREATE TABLE pa_application_config (id int NOT NULL, application_id int NOT NULL, config_key varchar(255) NOT NULL, config_values varchar (max), CONSTRAINT PK_PA_APPLICATION_CONFIG PRIMARY KEY (id), CONSTRAINT pa_app_config_app_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::2::Roman Strobl
-- Create a new index on pa_application_config(config_key)
CREATE NONCLUSTERED INDEX pa_app_config_key_idx ON pa_application_config(config_key);
GO

-- Changeset powerauth-java-server/1.7.x/20240212-application-config.xml::3::Lubos Racansky
-- Create a new sequence pa_app_conf_seq
CREATE SEQUENCE pa_app_conf_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/1.7.x/20240312-fido2-authenticator.xml::1::Jan Pesek
-- Create a new table pa_fido2_authenticator
CREATE TABLE pa_fido2_authenticator (aaguid varchar(255) NOT NULL, description varchar(255) NOT NULL, signature_type varchar(255) NOT NULL, CONSTRAINT PK_PA_FIDO2_AUTHENTICATOR PRIMARY KEY (aaguid));
GO

-- Changeset powerauth-java-server/1.7.x/20240222-add-tag-1.7.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::1::Jan Pesek
-- Drop index on pa_operation(timestamp_expires, status).
DROP INDEX pa_operation_status_exp ON pa_operation;
GO

-- Changeset powerauth-java-server/1.8.x/20240424-index-expire-status.xml::2::Jan Pesek
-- Create a new index on pa_operation(status, timestamp_expires).
CREATE NONCLUSTERED INDEX pa_operation_status_exp ON pa_operation(status, timestamp_expires);
GO

-- Changeset powerauth-java-server/1.8.x/20240517-fido2-authenticator-transports.xml::1::Jan Pesek
-- Add transports column in pa_fido2_authenticator table.
ALTER TABLE pa_fido2_authenticator ADD transports varchar(255);
GO

-- Changeset powerauth-java-server/1.8.x/20240529-add-status-reason.xml::1::Lubos Racansky
-- Add status_reason column to pa_operation table.
ALTER TABLE pa_operation ADD status_reason varchar(32);
GO

-- Changeset powerauth-java-server/1.8.x/20240625-add-tag-1.8.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::1::Petr Dvorak
-- Create a new table pa_temporary_key
CREATE TABLE pa_temporary_key (id varchar(37) NOT NULL, application_key varchar(32) NOT NULL, activation_id varchar(37), private_key_encryption int CONSTRAINT DF_pa_temporary_key_private_key_encryption DEFAULT 0 NOT NULL, private_key_base64 varchar(255) NOT NULL, public_key_base64 varchar(255) NOT NULL, timestamp_expires datetime2 NOT NULL, CONSTRAINT PK_PA_TEMPORARY_KEY PRIMARY KEY (id), CONSTRAINT pa_temporary_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/1.9.x/20240718-add-temporary-keys.xml::2::Petr Dvorak
-- Create a new index on pa_temporary_key(timestamp_expires)
CREATE NONCLUSTERED INDEX pa_temporary_key_ts_key_idx ON pa_temporary_key(timestamp_expires);
GO

-- Changeset powerauth-java-server/1.9.x/20240723-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_config table.
ALTER TABLE pa_application_config ADD encryption_mode varchar(255) CONSTRAINT DF_pa_application_config_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL;
GO

-- Changeset powerauth-java-server/1.9.x/20240906-configuration-encryption.xml::1::Lubos Racansky
-- Add encryption_mode column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD encryption_mode varchar(255) CONSTRAINT DF_pa_application_callback_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL;
GO

-- Changeset powerauth-java-server/1.9.x/20240910-commit-phase.xml::1::Roman Strobl
-- Add commit_phase column to pa_activation table.
ALTER TABLE pa_activation ADD commit_phase int CONSTRAINT DF_pa_activation_commit_phase DEFAULT 0;
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::1::Jan Pesek
-- Create a new table pa_application_callback_event
CREATE TABLE pa_application_callback_event (id bigint NOT NULL, application_callback_id varchar(37) NOT NULL, callback_data varchar (max) NOT NULL, status varchar(32) NOT NULL, timestamp_created datetime2(6) CONSTRAINT DF_pa_application_callback_event_timestamp_created DEFAULT GETDATE() NOT NULL, timestamp_last_call datetime2(6), timestamp_next_call datetime2(6), timestamp_delete_after datetime2(6), timestamp_rerun_after datetime2(6), attempts int CONSTRAINT DF_pa_application_callback_event_attempts DEFAULT 0 NOT NULL, idempotency_key varchar(36) NOT NULL, CONSTRAINT PK_PA_APPLICATION_CALLBACK_EVENT PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::2::Jan Pesek
-- Add max_attempts column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD max_attempts int;
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::3::Jan Pesek
-- Add initial_backoff column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD initial_backoff varchar(64);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::4::Jan Pesek
-- Add retention_period column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD retention_period varchar(64);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::5::Jan Pesek
-- Create a new index on pa_application_callback_event(status).
CREATE NONCLUSTERED INDEX pa_app_cb_event_status_idx ON pa_application_callback_event(status);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::6::Jan Pesek
-- Create a new index on pa_application_callback_event(timestamp_delete_after).
CREATE NONCLUSTERED INDEX pa_app_cb_event_ts_del_idx ON pa_application_callback_event(timestamp_delete_after);
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::7::Jan Pesek
-- Create a new sequence pa_app_callback_event_seq
CREATE SEQUENCE pa_app_callback_event_seq START WITH 1 INCREMENT BY 50 CACHE 20;
GO

-- Changeset powerauth-java-server/1.9.x/20240704-callback-event-table.xml::10::Jan Pesek
-- Add enabled column to pa_application_callback table.
ALTER TABLE pa_application_callback ADD enabled bit CONSTRAINT DF_pa_application_callback_enabled DEFAULT 1 NOT NULL;
GO

-- Changeset powerauth-java-server/1.9.x/20241010-rest-client-caching.xml::1::Jan Pesek
-- Add columns timestamp_last_updated and timestamp_created to pa_application_callback table
ALTER TABLE pa_application_callback ADD timestamp_created datetime2(6) CONSTRAINT DF_pa_application_callback_timestamp_created DEFAULT GETDATE() NOT NULL;
GO

ALTER TABLE pa_application_callback ADD timestamp_last_updated datetime2(6);
GO

-- Changeset powerauth-java-server/1.9.x/20241003-add-tag-1.9.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/1.10.x/20250609-activation-additional-data.xml::1::Lubos Racansky
-- Add additional_data column to pa_activation table.
ALTER TABLE pa_activation ADD additional_data varchar (max);
GO

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::1::Roman Strobl
-- Add column crypto_algorithm to pa_activation table
ALTER TABLE pa_activation ADD crypto_algorithm varchar(32);
GO

-- Changeset powerauth-java-server/2.0.x/20250314-crypto4-pqc.xml::2::Roman Strobl
-- Add new columns for crypto4 keys to pa_activation table
ALTER TABLE pa_activation ADD shared_secret varchar(255);
GO

ALTER TABLE pa_activation ADD shared_secret_encryption int CONSTRAINT DF_pa_activation_shared_secret_encryption DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250317-crypto4-master-keys.xml::1::Roman Strobl
-- Add columns for crypto4 keys to pa_master_keypair table
ALTER TABLE pa_master_keypair ADD master_private_keys varchar(MAX);
GO

ALTER TABLE pa_master_keypair ADD master_private_keys_encryption int CONSTRAINT DF_pa_master_keypair_master_private_keys_encryption DEFAULT 0 NOT NULL;
GO

ALTER TABLE pa_master_keypair ADD master_public_keys varchar(MAX);
GO

-- Changeset powerauth-java-server/2.0.x/20250318-crypto4-dynamic-keys.xml::1::Roman Strobl
-- Add columns for crypto4 dynamic keys to pa_activation table
ALTER TABLE pa_activation ADD biometric_factor_enabled bit CONSTRAINT DF_pa_activation_biometric_factor_enabled DEFAULT 0;
GO

ALTER TABLE pa_activation ADD biometric_factor_key varchar(255);
GO

ALTER TABLE pa_activation ADD biometric_factor_key_next varchar(255);
GO

ALTER TABLE pa_activation ADD knowledge_factor_key varchar(255);
GO

ALTER TABLE pa_activation ADD knowledge_factor_key_next varchar(255);
GO

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::1::Roman Strobl
-- Add columns for crypto4 shared secret storage to pa_temporary_key table
ALTER TABLE pa_temporary_key ADD secret_key_base64 varchar(255);
GO

ALTER TABLE pa_temporary_key ADD secret_key_encryption int CONSTRAINT DF_pa_temporary_key_secret_key_encryption DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250320-crypto4-temporary-keys.xml::2::Roman Strobl
-- Change the temporary keypair columns to nullable in pa_temporary_key table
ALTER TABLE pa_temporary_key ALTER COLUMN private_key_base64 varchar(255) NULL;
GO

ALTER TABLE pa_temporary_key ALTER COLUMN public_key_base64 varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20250709-crypto4-activation-confirmation.xml::1::Roman Strobl
-- Add column confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD confirmation_pending bit CONSTRAINT DF_pa_activation_confirmation_pending DEFAULT 0;
GO

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::1::Roman Strobl
-- Add column upgrade_confirmation_pending to pa_activation table
ALTER TABLE pa_activation ADD upgrade_confirmation_pending bit CONSTRAINT DF_pa_activation_upgrade_confirmation_pending DEFAULT 0;
GO

-- Changeset powerauth-java-server/2.0.x/20250925-crypto4-upgrade.xml::2::Roman Strobl
-- Add column ctr_data_v4 to pa_activation table
ALTER TABLE pa_activation ADD ctr_data_v4 varchar(255);
GO

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::1::Lubos Racansky
-- Add column parent_activation_id to pa_activation table
ALTER TABLE pa_activation ADD parent_activation_id varchar(37);
GO

ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_parent_activation_id_fk FOREIGN KEY (parent_activation_id) REFERENCES pa_activation (activation_id);
GO

-- Changeset powerauth-java-server/2.0.x/20251005-activation-parent-id.xml::2::Lubos Racansky
-- Add column transfer_type to pa_activation table
ALTER TABLE pa_activation ADD transfer_type varchar(32);
GO

-- Changeset powerauth-java-server/2.0.x/20251106-allow-null-legacy-keypairs.xml::1::Roman Strobl
-- Change the master keypair columns to nullable in pa_master_keypair table
ALTER TABLE pa_master_keypair ALTER COLUMN master_key_private_base64 varchar(255) NULL;
GO

ALTER TABLE pa_master_keypair ALTER COLUMN master_key_public_base64 varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::1::Jan Pesek
-- Change the server_private_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation ALTER COLUMN server_private_key_base64 varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20251231-allow-null-legacy-server-keypair.xml::2::Jan Pesek
-- Change the server_public_key_base64 column to nullable in the pa_activation table
ALTER TABLE pa_activation ALTER COLUMN server_public_key_base64 varchar(255) NULL;
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::1::Jan Pesek
-- Create a new sequence pa_device_public_key_seq
CREATE SEQUENCE pa_device_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::2::Jan Pesek
-- Create a new table pa_device_public_key
CREATE TABLE pa_device_public_key (id bigint CONSTRAINT DF_pa_device_public_key_id DEFAULT NEXT VALUE FOR pa_device_public_key_seq NOT NULL, key_data varchar(MAX), CONSTRAINT PK_PA_DEVICE_PUBLIC_KEY PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::3::Jan Pesek
-- Create a new sequence pa_server_public_key_seq
CREATE SEQUENCE pa_server_public_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::4::Jan Pesek
-- Create a new table pa_server_public_key
CREATE TABLE pa_server_public_key (id bigint CONSTRAINT DF_pa_server_public_key_id DEFAULT NEXT VALUE FOR pa_server_public_key_seq NOT NULL, key_data varchar(MAX), CONSTRAINT PK_PA_SERVER_PUBLIC_KEY PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::5::Jan Pesek
-- Create a new sequence pa_server_private_key_seq
CREATE SEQUENCE pa_server_private_key_seq START WITH 1 INCREMENT BY 1 CACHE 20;
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::6::Jan Pesek
-- Create a new table pa_server_private_key
CREATE TABLE pa_server_private_key (id bigint CONSTRAINT DF_pa_server_private_key_id DEFAULT NEXT VALUE FOR pa_server_private_key_seq NOT NULL, key_data varchar(MAX), key_data_encryption int CONSTRAINT DF_pa_server_private_key_key_data_encryption DEFAULT 0 NOT NULL, CONSTRAINT PK_PA_SERVER_PRIVATE_KEY PRIMARY KEY (id));
GO

-- Changeset powerauth-java-server/2.0.x/20251222-crypto4-keys-tables.xml::7::Jan Pesek
-- Add new crypto4 key referencing columns to pa_activation table
ALTER TABLE pa_activation ADD device_public_key_id bigint;
GO

ALTER TABLE pa_activation ADD CONSTRAINT pa_device_public_key_id_fk FOREIGN KEY (device_public_key_id) REFERENCES pa_device_public_key (id);
GO

ALTER TABLE pa_activation ADD server_private_key_id bigint;
GO

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_private_key_id_fk FOREIGN KEY (server_private_key_id) REFERENCES pa_server_private_key (id);
GO

ALTER TABLE pa_activation ADD server_public_key_id bigint;
GO

ALTER TABLE pa_activation ADD CONSTRAINT pa_server_public_key_id_fk FOREIGN KEY (server_public_key_id) REFERENCES pa_server_public_key (id);
GO

-- Changeset powerauth-java-server/2.0.x/20260107-crypto4-store-fingerprint.xml::1::Jan Pesek
-- Add column activation_fingerprint to pa_activation table
ALTER TABLE pa_activation ADD activation_fingerprint varchar(255);
GO

-- Changeset powerauth-java-server/2.0.x/20251215-add-tag-2.0.0.xml::1::Lubos Racansky
-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-fix-nulls.xml::1::Vit Kotacka
-- Retrofit NULL activation_code values with unique LEGACY- prefixed placeholders
--             before adding the NOT NULL constraint. Skipped automatically (MARK_RAN) if no
--             NULL values are present, which is the expected case for all non-legacy databases.
--             Rollback is not supported — original NULL values cannot be restored.
UPDATE pa_activation
SET activation_code = 'LEGACY-' + LOWER(CONVERT(varchar(36), NEWID()))
WHERE activation_code IS NULL;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::0::Vit Kotacka
-- MSSQL only: drop non-unique index pa_activation_code before ALTER COLUMN. MSSQL blocks ALTER COLUMN when a dependent index exists (error 5074); PostgreSQL and Oracle do not have this restriction.
DROP INDEX pa_activation_code ON pa_activation;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::1::Vit Kotacka
-- Add NOT NULL constraint on pa_activation(activation_code) to align the DB schema with the JPA entity definition. Applied before the unique constraint to fail fast if NULL values exist, avoiding an expensive index build on dirty data.
ALTER TABLE pa_activation ALTER COLUMN activation_code varchar(255) NOT NULL;
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::2::Vit Kotacka
-- Add unique constraint on (activation_code, application_id) to enforce activation code uniqueness at DB level, replacing the application-level SELECT COUNT uniqueness check. activation_code is NOT NULL (see changeset id=1), so multiple NULLs bypassing the unique constraint is not a concern.
ALTER TABLE pa_activation ADD CONSTRAINT pa_activation_code_application_uk UNIQUE (activation_code, application_id);
GO

-- Changeset powerauth-java-server/2.1.x/20260316-activation-code-unique.xml::3::Vit Kotacka
-- Safety-net drop of non-unique index pa_activation_code. Normally already dropped by id=0; this changeset is a no-op (MARK_RAN) on fresh installs but ensures correctness on environments that ran id=1..3 before id=0 was introduced.
DROP INDEX pa_activation_code ON pa_activation;
GO

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::1::Pavel Sindelar
-- Add subject_id column to audit_log table
ALTER TABLE audit_log ADD subject_id varchar(256);
GO

-- Changeset powerauth-java-server/2.1.x/20260327-audit-subject-id.xml::2::Pavel Sindelar
-- Create a new index on audit_log(subject_id)
CREATE NONCLUSTERED INDEX audit_log_subject_id_idx ON audit_log(subject_id);
GO

-- Changeset powerauth-java-server/2.1.x/20260416-add-tag-2.1.0.xml::1::Pavel Sindelar
-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::1::Roman Strobl
-- Add signature_algorithm column to pa_signature_audit table to store signature algorithm
ALTER TABLE pa_signature_audit ADD signature_algorithm varchar(32);
GO

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::2::Roman Strobl
-- Add signature_format column to pa_signature_audit table to store the asymmetric signature format (DER/JOSE)
ALTER TABLE pa_signature_audit ADD signature_format varchar(32);
GO

-- Changeset powerauth-java-server/2.2.x/20260428-asymmetric-signature-audit.xml::3::Roman Strobl
-- Change data type of signature column in pa_signature_audit table from varchar(255) to text to support longer asymmetric signatures
ALTER TABLE pa_signature_audit ALTER COLUMN signature varchar (max);
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::1::Roman Strobl
-- Add timestamp_block_expire column to pa_activation table to support automatic temporary unblocking of activations
ALTER TABLE pa_activation ADD timestamp_block_expire datetime2(6);
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::2::Roman Strobl
-- Add temporary_block_count column to pa_activation table to extend the block period for consecutive blocks
ALTER TABLE pa_activation ADD temporary_block_count bigint CONSTRAINT DF_pa_activation_temporary_block_count DEFAULT 0 NOT NULL;
GO

-- Changeset powerauth-java-server/2.2.x/20260527-activation-temporary-block.xml::3::Roman Strobl
-- Create a partial index on pa_activation(timestamp_block_expire) to support the scheduled expiration of temporary activation blocks (on Oracle a plain single-column index achieves the same effect, since all-null keys are not indexed)
CREATE NONCLUSTERED INDEX pa_activation_block_expire_idx ON pa_activation(timestamp_block_expire) WHERE timestamp_block_expire IS NOT NULL;
GO


-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::1::Roman Strobl
-- Create a new table pa_config_store
CREATE TABLE pa_config_store (id bigint NOT NULL, application_id int NOT NULL, activation_id varchar(37), scope varchar(32) NOT NULL, config_data varchar (max), encryption_mode varchar(255) CONSTRAINT DF_pa_config_store_encryption_mode DEFAULT 'NO_ENCRYPTION' NOT NULL, timestamp_created datetime2(6) NOT NULL, timestamp_last_updated datetime2(6), CONSTRAINT PK_PA_CONFIG_STORE PRIMARY KEY (id), CONSTRAINT pa_config_store_application_id_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT pa_config_store_activation_id_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::2::Roman Strobl
-- Create a new sequence pa_config_store_seq
CREATE SEQUENCE pa_config_store_seq START WITH 1 INCREMENT BY 50 CACHE 20;
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::3::Roman Strobl
-- Create a new index on pa_config_store(application_id)
CREATE NONCLUSTERED INDEX pa_config_store_application_id_idx ON pa_config_store(application_id);
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::4::Roman Strobl
-- Create a new index on pa_config_store(activation_id)
CREATE NONCLUSTERED INDEX pa_config_store_activation_id_idx ON pa_config_store(activation_id);
GO

-- Changeset powerauth-java-server/2.2.x/20260602-config-store.xml::5::Roman Strobl
-- Create a unique index on pa_config_store(application_id, activation_id, scope).
CREATE UNIQUE NONCLUSTERED INDEX pa_config_store_application_id_activation_id_scope_idx ON pa_config_store(application_id, activation_id, scope);
GO
