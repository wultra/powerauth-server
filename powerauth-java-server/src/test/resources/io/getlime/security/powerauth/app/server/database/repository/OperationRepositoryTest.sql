INSERT INTO pa_application (id, name, roles)
VALUES (21, 'PA_Tests', '[ "ROLE3", "ROLE4" ]'), (22, 'PA_Tests2', '[ "ROLE3", "ROLE4" ]');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, name, timestamp_created) VALUES
    (21, 21, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 'PA_Tests Default Keypair', '2022-06-07 09:13:27.599000');

INSERT INTO pa_activation (activation_id, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, version)
VALUES ('e43a5dec-afea-4a10-a80b-b2183399f16b', 21, 'testUser', 'test v4', 'PXSNR-E2B46-7TY3G-TMR2Q', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[ "test-flag1", "test-flag2", "test-flag3" ]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', '2023-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 21, 3);

insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('0f038bac-6c94-45eb-b3a9-f92e809e8ea4', 'testUser', null, 'test-flag1', 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2023-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, 'e43a5dec-afea-4a10-a80b-b2183399f16b');
/* NULL activation flag */
insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('70702b41-7b5a-4a6d-9bc2-e99949c2df53', 'testUser', null, null, 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2023-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, 'e43a5dec-afea-4a10-a80b-b2183399f16b');
/* NULL activation id */
insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('f451bcb7-9d76-42d6-97a6-76a9ecaf25813', 'testUser', null, null, 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2023-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, null);

insert into pa_operation_application (application_id, operation_id)
VALUES (21, '0f038bac-6c94-45eb-b3a9-f92e809e8ea4'), (22, '0f038bac-6c94-45eb-b3a9-f92e809e8ea4'),
 (21, '70702b41-7b5a-4a6d-9bc2-e99949c2df53'), (22, '70702b41-7b5a-4a6d-9bc2-e99949c2df53'),
 (21, 'f451bcb7-9d76-42d6-97a6-76a9ecaf25813'), (22, 'f451bcb7-9d76-42d6-97a6-76a9ecaf25813');