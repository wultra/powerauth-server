INSERT INTO pa_application (id, name, roles)
VALUES (100, 'test-app-activation', '[]'),
       (101, 'other-app-activation', '[]');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, master_private_keys_encryption, name, timestamp_created)
VALUES (100, 100, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 0, 'Test Default Keypair', '2024-01-01 00:00:00.000000'),
       (101, 101, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 0, 'Other Test Default Keypair', '2024-01-01 00:00:00.000000');

-- Activation in test-app-activation with code AAAAA-AAAAA-BBBBB-BBBBB
INSERT INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, shared_secret_encryption, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, biometric_factor_enabled, confirmation_pending, upgrade_confirmation_pending, version)
VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-111111111111', 100, 'user1', 'test', 'AAAAA-AAAAA-BBBBB-BBBBB', 3, null, 0, null, 0, null, null, null, 'unknown', 'test', '[]', 0, 5, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, null, 0, '2099-01-01 00:00:00.000000', '2024-01-01 00:00:00.000000', '2024-01-01 00:00:00.000000', null, 100, false, false, false, 3);

-- Activation in other-app-activation with a different code
INSERT INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, shared_secret_encryption, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, biometric_factor_enabled, confirmation_pending, upgrade_confirmation_pending, version)
VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-111111111111', 101, 'user2', 'test', 'DDDDD-DDDDD-DDDDD-DDDDD', 3, null, 0, null, 0, null, null, null, 'unknown', 'test', '[]', 0, 5, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, null, 0, '2099-01-01 00:00:00.000000', '2024-01-01 00:00:00.000000', '2024-01-01 00:00:00.000000', null, 101, false, false, false, 3);
