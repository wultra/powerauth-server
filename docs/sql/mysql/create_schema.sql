--
-- Create tables for applications and application versions
--

CREATE TABLE `pa_application` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `roles` varchar(255),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `pa_application_version` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `application_key` varchar(255) DEFAULT NULL,
  `application_secret` varchar(255) DEFAULT NULL,
  `supported` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_APPLICATION_VERSION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for application related master keypair
--

CREATE TABLE `pa_master_keypair` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `master_key_private_base64` varchar(255) NOT NULL,
  `master_key_public_base64` varchar(255) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_APPLICATION_KEYPAIR` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for activation records
--

CREATE TABLE `pa_activation` (
  `activation_id` varchar(37) NOT NULL,
  `activation_code` varchar(255),
  `activation_status` int(11) NOT NULL,
  `activation_otp` varchar(255),
  `activation_otp_validation` int DEFAULT 0 NOT NULL,
  `blocked_reason` varchar(255) DEFAULT NULL,
  `activation_name` varchar(255) DEFAULT NULL,
  `application_id` bigint(20) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `extras` text,
  `platform` varchar(255),
  `device_info` varchar(255),
  `flags` varchar(255),
  `counter` bigint(20) NOT NULL,
  `ctr_data` varchar(255),
  `device_public_key_base64` text,
  `failed_attempts` bigint(20) DEFAULT NULL,
  `max_failed_attempts` bigint(20) NOT NULL DEFAULT 5,
  `server_private_key_base64` text NOT NULL,
  `server_private_key_encryption` int(11) NOT NULL DEFAULT 0,
  `server_public_key_base64` text NOT NULL,
  `master_keypair_id` bigint(20) DEFAULT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `timestamp_activation_expire` datetime NOT NULL,
  `timestamp_last_used` datetime NOT NULL,
  `timestamp_last_change` datetime,
  `version` int(2) DEFAULT 2,
  PRIMARY KEY (`activation_id`),
  CONSTRAINT `FK_ACTIVATION_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `FK_ACTIVATION_KEYPAIR` FOREIGN KEY (`master_keypair_id`) REFERENCES `pa_master_keypair` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create a table for signature audits
--

CREATE TABLE `pa_signature_audit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) NOT NULL,
  `activation_counter` bigint(20) NOT NULL,
  `activation_ctr_data` varchar(255),
  `activation_status` int(11) NOT NULL,
  `additional_info` varchar(255) DEFAULT NULL,
  `data_base64` text,
  `signature_type` varchar(255) NOT NULL,
  `signature` varchar(255) NOT NULL,
  `valid` int(11) NOT NULL DEFAULT 0,
  `note` text NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `version` int(2) DEFAULT 2,
  `signature_version` varchar(255),
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create a table for integration credentials
--

CREATE TABLE `pa_integration` (
  `id` varchar(37) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `client_token` varchar(37) DEFAULT NULL,
  `client_secret` varchar(37) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create a table for callback URLs
--

CREATE TABLE `pa_application_callback` (
  `id` varchar(37) NOT NULL,
  `application_id` bigint(20) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `callback_url` text NOT NULL,
  `type` VARCHAR(64) DEFAULT 'ACTIVATION_STATUS_CHANGE' NOT NULL,
  `attributes` text NOT NULL,
  `authentication` text,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_APPLICATION_CALLBACK` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create a table for tokens
--

CREATE TABLE `pa_token` (
	`token_id` varchar(37) NOT NULL,
	`token_secret` varchar(255) NOT NULL,
	`activation_id` varchar(37) NOT NULL,
	`signature_type` varchar(255) NOT NULL,
	`timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`token_id`),
  CONSTRAINT `FK_TOKEN_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for activation changes
--

CREATE TABLE `pa_activation_history` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `event_reason` varchar(255),
  `external_user_id` varchar(255),
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_HISTORY_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for recovery codes
--

CREATE TABLE `pa_recovery_code` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `recovery_code` varchar(23) NOT NULL,
  `application_id` bigint(20) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `activation_id` varchar(37),
  `status` int(11) NOT NULL,
  `failed_attempts` bigint(20) NOT NULL,
  `max_failed_attempts` bigint(20) NOT NULL,
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
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `recovery_code_id` bigint(20) NOT NULL,
  `puk` varchar(255) NOT NULL,
  `puk_encryption` int(11) NOT NULL DEFAULT 0,
  `puk_index` int(11) NOT NULL,
  `status` int(11) NOT NULL,
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
  `postcard_priv_key_encryption` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_RECOVERY_CONFIG_APP` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for operations
--
CREATE TABLE pa_operation (
    id varchar(37) NOT NULL,
    user_id varchar(255) NOT NULL,
    application_id bigint(20) NOT NULL,
    external_id varchar(255) NULL,
    operation_type varchar(255) NOT NULL,
    data text NOT NULL,
    parameters text NULL,
    status int(11) NOT NULL,
    signature_type varchar(255) NOT NULL,
    failure_count bigint(20) default 0 NOT NULL,
    max_failure_count bigint(20) NOT NULL,
    timestamp_created datetime NOT NULL,
    timestamp_expires datetime NOT NULL,
    timestamp_finalized datetime NULL,
    PRIMARY KEY (id),
    CONSTRAINT `FK_OPERATION_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE NO ACTION ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for operation templates
--
CREATE TABLE pa_operation_template (
    id bigint(20) NOT NULL AUTO_INCREMENT,
    template_name varchar(255) NOT NULL,
    operation_type varchar(255) NOT NULL,
    data_template varchar(255) NOT NULL,
    signature_type varchar(255) NOT NULL,
    max_failure_count bigint(20) NOT NULL,
    expiration bigint(20) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- DDL for Table SHEDLOCK
--
CREATE TABLE shedlock (
    name VARCHAR(64) NOT NULL,
    lock_until TIMESTAMP(3) NOT NULL,
    locked_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    locked_by VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Indexes for better performance. InnoDB engine creates indexes on foreign keys automatically, so they are not included.
--

CREATE INDEX `pa_activation_code` ON `pa_activation`(`activation_code`);

CREATE INDEX `pa_activation_user_id` ON `pa_activation`(`user_id`);

CREATE INDEX `pa_activation_history_created` ON `pa_activation_history`(`timestamp_created`);

CREATE UNIQUE INDEX `pa_app_version_app_key` ON `pa_application_version`(`application_key`);

CREATE INDEX `pa_app_callback_app` ON `pa_application_callback`(`application_id`);

CREATE UNIQUE INDEX `pa_integration_token` ON `pa_integration`(`client_token`);

CREATE INDEX `pa_signature_audit_created` ON `pa_signature_audit`(`timestamp_created`);

CREATE INDEX `pa_recovery_code` ON `pa_recovery_code`(`recovery_code`);

CREATE INDEX `pa_recovery_code_user` ON `pa_recovery_code`(`user_id`);

CREATE INDEX `pa_operation_user` ON `pa_operation`(`user_id`);

CREATE INDEX `pa_operation_ts_created_idx` ON `pa_operation`(`timestamp_created`);

CREATE INDEX `pa_operation_ts_expires_idx` ON `pa_operation`(`timestamp_expires`);

CREATE INDEX `pa_operation_template_name_idx` ON `pa_operation_template` (`template_name`);

CREATE UNIQUE INDEX `pa_recovery_code_puk` ON `pa_recovery_puk`(`recovery_code_id`, `puk_index`);

CREATE UNIQUE INDEX `pa_application_name` ON `pa_application`(`name`);
