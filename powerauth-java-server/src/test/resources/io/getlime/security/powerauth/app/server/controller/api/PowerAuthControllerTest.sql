INSERT INTO pa_application (id, name, roles) VALUES
    (21, 'PA_Tests', '[ "ROLE3", "ROLE4" ]');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, name, timestamp_created)
VALUES (21, 21, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 'PA_Tests Default Keypair', '2022-06-07 09:13:27.599000');

INSERT INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, version) VALUES
    ('e43a5dec-afea-4a10-a80b-b2183399f16b', 21, 'TestUserV3_d8c2e122-b12a-47f1-bca7-e04637bffd14', 'test v3', 'PXSNR-E2B46-7TY3G-TMR2Q', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[ ]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', '2023-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 21, 3);

INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration, proximity_check_enabled)
VALUES (101, 'test-template', 'test-template', 'A2', 'POSSESSION_KNOWLEDGE', 5, 300, false);