INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration, proximity_check_enabled)
VALUES (100, 'test-template', 'test-template', 'A2', 'POSSESSION_KNOWLEDGE', 5, 300, false);

INSERT INTO pa_application (id, name) VALUES
    (21, 'PA_Tests');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, name, timestamp_created) VALUES
(21, 21, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 'PA_Tests Default Keypair', '2022-06-07 09:13:27.599000');

INSERT INTO pa_activation (activation_id, protocol, application_id, user_id, activation_name, activation_code, activation_status, activation_otp, activation_otp_validation, blocked_reason, counter, ctr_data, device_public_key_base64, extras, platform, device_info, flags, failed_attempts, max_failed_attempts, server_private_key_base64, server_private_key_encryption, server_public_key_base64, timestamp_activation_expire, timestamp_created, timestamp_last_used, timestamp_last_change, master_keypair_id, version) VALUES
('e43a5dec-afea-4a10-a80b-b2183399f16b', 'powerauth', 21, 'testUser', 'test v4', 'PXSNR-E2B46-7TY3G-TMR2Q', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[ "test-flag1", "test-flag2", "test-flag3" ]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', '2023-04-03 14:04:06.015000', '2023-04-03 13:59:06.015000', '2023-04-03 13:59:16.293000', '2023-04-03 13:59:16.343000', 21, 3),
('68c5ca56-b419-4653-949f-49061a4be886', 'powerauth', 21, 'testUser', 'test v4', 'PVHMP-NQEZ6-ADSYV-HRSYA', 3, null, 0, null, 0, 'D5XibWWPCv+nOOfcdfnUGQ==', 'BF3Sc/vqg8Zk70Y8rbT45xzAIxblGoWgLqknCHuNj7f6QFBNi2UnLbG7yMqf2eWShhyBJdu9zqx7DG2qzlqhbBE=', null, 'unknown', 'backend-tests', '[ "test-flag1", "test-flag4", "test-flag5" ]', 0, 1, 'PUz/He8+RFoOPS1NG6Gw3TDXIQ/DnS1skNBOQWzXX60=', 0, 'BPHJ4N90NUuLDq92FJUPcaKZOMad1KH2HrwQEN9DB5ST5fiJU4baYF1VlK1JHglnnN1miL3/Qb6IyW3YSMBySYM=', '2023-04-03 14:04:06.015000', '9999-04-03 13:59:06.015000', '9999-04-03 13:59:16.293000', '9999-04-03 13:59:16.343000', 21, 3);

insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('0f038bac-6c94-45eb-b3a9-f92e809e8ea4', 'testUser', null, 'test-flag5', 'login', 'test', 'A2', null, null, 1,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2023-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, 'e43a5dec-afea-4a10-a80b-b2183399f16b');
/* NULL activation flag */
insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('70702b41-7b5a-4a6d-9bc2-e99949c2df53', 'testUser', null, 'test-flag1', 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2025-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, 'e43a5dec-afea-4a10-a80b-b2183399f16b');
/* NULL activation id */
insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('f451bcb7-9d76-42d6-97a6-76a9ecaf25813', 'testUser', null, 'test-flag1', 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2024-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, null);

insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('b6e41a83-6357-4670-ac4c-1f7dcaf2aa9e', 'testUser', null, 'test-flag3', 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2026-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, '68c5ca56-b419-4653-949f-49061a4be886');

insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('e708e33e-e1cb-48e2-9b51-521a3d205330', 'testUser', null, null, 'login', 'test', 'A2', null, null, 3,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2027-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, '68c5ca56-b419-4653-949f-49061a4be886');

insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('2067b5d1-1c50-43eb-99df-847830e4807a', 'testUser', null, null, 'login', 'test', 'A2', null, null, 1,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2021-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', null, null, null, '68c5ca56-b419-4653-949f-49061a4be886');
/* TO be expired*/
insert into pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id)
VALUES ('2067b5d1-1c50-43eb-99df-847830eaaaa', 'testUser', null, null, 'login', 'test', 'A2', null, null, 1,'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 0, 5, '2020-12-14 21:56:40.773000', '2021-12-14 21:56:40.773000', null, null, null, '68c5ca56-b419-4653-949f-49061a4be886');

insert into pa_operation_application (application_id, operation_id)
VALUES (21, '0f038bac-6c94-45eb-b3a9-f92e809e8ea4'),
 (21, '70702b41-7b5a-4a6d-9bc2-e99949c2df53'),
 (21, 'f451bcb7-9d76-42d6-97a6-76a9ecaf25813'),
 (21, 'b6e41a83-6357-4670-ac4c-1f7dcaf2aa9e'),
 (21, 'e708e33e-e1cb-48e2-9b51-521a3d205330'),
 (21, '2067b5d1-1c50-43eb-99df-847830e4807a'),
 (21, '2067b5d1-1c50-43eb-99df-847830eaaaa');