INSERT INTO pa_application (id, name) VALUES
    (1, 'PA_Tests');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, name, timestamp_created) VALUES
    (1, 1, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 'PA_Tests Default Keypair', '2020-10-04 12:13:27.599000');

INSERT INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, version) VALUES
    ('e43a5dec-afea-4a10-a80b-b2183399f16b', 1, 'testUser', 'test v4', 'PXSNR-E2B46-7TY3G-TMR2Q', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[ "test-flag1", "test-flag2", "test-flag3" ]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', '2023-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 1, 3);

INSERT INTO pa_application_callback (id, application_id, name, callback_url, type, failure_count, enabled) VALUES
    ('cba5f7aa-889e-4846-b97a-b6ba1bd51ad5', 1, 'test-callback-enabled', 'http://localhost:8080', 'ACTIVATION_STATUS_CHANGE', 0, true),
    ('b5446f8f-a994-447e-b637-e7cd171a24b5', 1, 'test-callback-disabled', 'http://localhost:8080', 'ACTIVATION_STATUS_CHANGE', 0, false),
    ('be335b28-8474-41a6-82c8-19ff8b7e82d2', 1, 'test-callback-operation', 'http://localhost:8080', 'OPERATION_STATUS_CHANGE', 0, true);
