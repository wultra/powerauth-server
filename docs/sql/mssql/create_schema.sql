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
CREATE SEQUENCE pa_application_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::2::Lubos Racansky
-- Create a new sequence pa_application_version_seq
CREATE SEQUENCE pa_application_version_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::3::Lubos Racansky
-- Create a new sequence pa_master_keypair_seq
CREATE SEQUENCE pa_master_keypair_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::4::Lubos Racansky
-- Create a new sequence pa_signature_audit_seq
CREATE SEQUENCE pa_signature_audit_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::5::Lubos Racansky
-- Create a new sequence pa_activation_history_seq
CREATE SEQUENCE pa_activation_history_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::6::Lubos Racansky
-- Create a new sequence pa_recovery_code_seq
CREATE SEQUENCE pa_recovery_code_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::7::Lubos Racansky
-- Create a new sequence pa_recovery_puk_seq
CREATE SEQUENCE pa_recovery_puk_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::8::Lubos Racansky
-- Create a new sequence pa_recovery_config_seq
CREATE SEQUENCE pa_recovery_config_seq START WITH 1 INCREMENT BY 1;
GO

-- Changeset powerauth-java-server/1.4.x/20230322-init-db.xml::9::Lubos Racansky
-- Create a new sequence pa_operation_template_seq
CREATE SEQUENCE pa_operation_template_seq START WITH 1 INCREMENT BY 1;
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
CREATE TABLE pa_activation (activation_id varchar(37) NOT NULL, application_id int NOT NULL, user_id varchar(255) NOT NULL, activation_name varchar(255), activation_code varchar(255), activation_status int NOT NULL, activation_otp varchar(255), activation_otp_validation int CONSTRAINT DF_pa_activation_activation_otp_validation DEFAULT 0 NOT NULL, blocked_reason varchar(255), counter int NOT NULL, ctr_data varchar(255), device_public_key_base64 varchar(255), extras varchar(255), platform varchar(255), device_info varchar(255), flags varchar(255), failed_attempts int NOT NULL, max_failed_attempts int CONSTRAINT DF_pa_activation_max_failed_attempts DEFAULT 5 NOT NULL, server_private_key_base64 varchar(255) NOT NULL, server_private_key_encryption int CONSTRAINT DF_pa_activation_server_private_key_encryption DEFAULT 0 NOT NULL, server_public_key_base64 varchar(255) NOT NULL, timestamp_activation_expire datetime2(6) NOT NULL, timestamp_created datetime2(6) NOT NULL, timestamp_last_used datetime2(6) NOT NULL, timestamp_last_change datetime2(6), master_keypair_id int, version int CONSTRAINT DF_pa_activation_version DEFAULT 2, CONSTRAINT PK_PA_ACTIVATION PRIMARY KEY (activation_id), CONSTRAINT activation_keypair_fk FOREIGN KEY (master_keypair_id) REFERENCES pa_master_keypair(id), CONSTRAINT activation_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id));
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
CREATE TABLE pa_recovery_code (id bigint NOT NULL, recovery_code varchar(23) NOT NULL, application_id int NOT NULL, user_id varchar(255) NOT NULL, activation_id varchar(37), status int NOT NULL, failed_attempts int CONSTRAINT DF_pa_recovery_code_failed_attempts DEFAULT 0 NOT NULL, max_failed_attempts int CONSTRAINT DF_pa_recovery_code_max_failed_attempts DEFAULT 10 NOT NULL, timestamp_created datetime2(6) NOT NULL, timestamp_last_used datetime2(6), timestamp_last_change datetime2(6), CONSTRAINT PK_PA_RECOVERY_CODE PRIMARY KEY (id), CONSTRAINT recovery_code_application_fk FOREIGN KEY (application_id) REFERENCES pa_application(id), CONSTRAINT recovery_code_activation_fk FOREIGN KEY (activation_id) REFERENCES pa_activation(activation_id));
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
