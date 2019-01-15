--
-- Create tables for applications and application versions
--

CREATE TABLE `pa_application` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
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
  `blocked_reason` varchar(255) DEFAULT NULL,
  `activation_name` varchar(255) DEFAULT NULL,
  `application_id` bigint(20) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `extras` text,
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
  CONSTRAINT `FK_ACTIVATION_APPLICATION` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
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
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_APPLICATION_CALLBACK` FOREIGN KEY (`application_id`) REFERENCES `pa_application` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create a table for tokens
--

CREATE TABLE pa_token (
	`token_id` VARCHAR(37) NOT NULL,
	`token_secret` VARCHAR(255) NOT NULL,
	`activation_id` VARCHAR(37) NOT NULL,
	`signature_type` VARCHAR(255) NOT NULL,
	`timestamp_created` DATETIME NOT NULL,
  PRIMARY KEY (`token_id`),
  CONSTRAINT `FK_TOKEN_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

--
-- Create table for activation changes
--

CREATE TABLE `pa_activation_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `activation_id` varchar(37) NOT NULL,
  `activation_status` int(11) NOT NULL,
  `timestamp_created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `FK_HISTORY_ACTIVATION_ID` FOREIGN KEY (`activation_id`) REFERENCES `pa_activation` (`activation_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=1 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

---
--- Indexes for better performance. InnoDB engine creates indexes on foreign keys automatically, so they are not included.
---

CREATE INDEX PA_ACTIVATION_CODE ON PA_ACTIVATION(ACTIVATION_CODE);

CREATE INDEX PA_ACTIVATION_USER_ID ON PA_ACTIVATION(USER_ID);

CREATE INDEX PA_ACTIVATION_HISTORY_CREATED ON PA_ACTIVATION_HISTORY(TIMESTAMP_CREATED);

CREATE UNIQUE INDEX PA_APP_VERSION_APP_KEY ON PA_APPLICATION_VERSION(APPLICATION_KEY);

CREATE INDEX PA_APP_CALLBACK_APP ON PA_APPLICATION_CALLBACK(APPLICATION_ID);

CREATE UNIQUE INDEX PA_INTEGRATION_TOKEN ON PA_INTEGRATION(CLIENT_TOKEN);

CREATE INDEX PA_SIGNATURE_AUDIT_CREATED ON PA_SIGNATURE_AUDIT(TIMESTAMP_CREATED);
