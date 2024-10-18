INSERT INTO pa_application (id, name) VALUES
    (21, 'PA_Tests');

INSERT INTO pa_application_callback (id, application_id, name, callback_url, type, enabled) VALUES
    ('cafec169-28a6-490c-a1d5-c012b9e3c044', 21, 'test-callback', 'http://localhost:8080', 'ACTIVATION_STATUS_CHANGE', true),
    ('c3d5083a-ce9f-467c-af2c-0c950c197bba', 21, 'test-callback', 'http://localhost:8080', 'ACTIVATION_STATUS_CHANGE', false);

INSERT INTO pa_application_callback_event (id, application_callback_id, callback_data, status, timestamp_created, attempts, idempotency_key) VALUES
    (1, 'cafec169-28a6-490c-a1d5-c012b9e3c044', '{}', 'COMPLETED', '2020-10-04 12:13:27.599000', 1, '729c3cd9-45e7-46b2-bc24-cd638138ccfe');
