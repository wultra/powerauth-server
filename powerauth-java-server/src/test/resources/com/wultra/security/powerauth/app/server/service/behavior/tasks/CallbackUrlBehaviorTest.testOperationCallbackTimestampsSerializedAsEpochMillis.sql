INSERT INTO pa_application (id, name) VALUES
    (1, 'PA_Tests');

INSERT INTO pa_master_keypair (id, application_id, master_key_private_base64, master_key_public_base64, master_private_keys_encryption, name, timestamp_created) VALUES
    (1, 1, 'KdcJHQAT/BBF+26uBGNhGC0GQ93ncTx7V6kusNA8AdE=', 'BP8ZZ0LjiwRCQPob3NFwF9pPDLhxCjnPNmENzayEeeGCiDdk0gl3UzUhYk9ntMg18LZdhpvYnprZ8mk/71WlQqo=', 0, 'PA_Tests Default Keypair', '2020-10-04 12:13:27.599000');

INSERT INTO pa_operation (id, user_id, external_id, activation_flag, operation_type, template_name, data, parameters, additional_data, status, signature_type, failure_count, max_failure_count, timestamp_created, timestamp_expires, timestamp_finalized, risk_flags, totp_seed, activation_id) VALUES
    ('07e927af-689a-43ac-bd21-291179801912', 'testUser', null, 'test-flag5', 'login', 'test', 'A2', null, null, 1,'possession,possession_knowledge,possession_biometry', 0, 5, '2023-12-14 21:56:40.773000', '9999-12-14 21:56:40.773000', '2023-12-15 10:00:00.000000', null, null, null);

INSERT INTO pa_operation_application (operation_id, application_id) VALUES
    ('07e927af-689a-43ac-bd21-291179801912', 1);

INSERT INTO pa_application_callback (id, application_id, name, callback_url, type, enabled, attributes) VALUES
    ('cba5f7aa-889e-4846-b97a-b6ba1bd51ad5', 1, 'test-callback-enabled', 'http://localhost:8080', 'OPERATION_STATUS_CHANGE', true, '["operationId","timestampCreated","timestampExpires","timestampFinalized"]');
