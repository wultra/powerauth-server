-- Test fixture for ConfigStoreLifecycleTest: one application with TWO active activations, so that the
-- "application-level ACTIVATION section shared across all devices" vs "per-device document isolated per
-- activation" behavior can be verified together.

DELETE FROM pa_config_store WHERE application_id = 221;

MERGE INTO pa_application (id, name) KEY(id) VALUES
    (221, 'PA_ConfigStore_Tests');

MERGE INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, master_private_keys_encryption, name, timestamp_created) KEY(id) VALUES
    (221, 221, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 0, 'PA_ConfigStore_Tests Default Keypair', '2022-06-07 09:13:27.599000');

MERGE INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, shared_secret_encryption, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, biometric_factor_enabled, confirmation_pending, upgrade_confirmation_pending, version) KEY(activation_id)
VALUES ('cf9a1100-0000-4000-8000-000000000001', 221, 'testUser', 'config store test device 1', 'PXSNR-E2B46-7TY3G-TMR2Q', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', 0, '9999-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 221, false, false, false, 3);

MERGE INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, shared_secret_encryption, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, biometric_factor_enabled, confirmation_pending, upgrade_confirmation_pending, version) KEY(activation_id)
VALUES ('cf9a1100-0000-4000-8000-000000000002', 221, 'testUser', 'config store test device 2', 'NXSNR-E2B46-7TY3G-TMR2A', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', 0, '9999-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 221, false, false, false, 3);

