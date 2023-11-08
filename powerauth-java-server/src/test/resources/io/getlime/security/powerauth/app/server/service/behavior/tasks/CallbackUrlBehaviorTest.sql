INSERT INTO pa_application (id, name) VALUES
    (21, 'PA_Tests');

INSERT INTO pa_application_callback (id, application_id, name, callback_url, type) VALUES
    ('cafec169-28a6-490c-a1d5-c012b9e3c044', 21, 'test-callback', 'http://localhost:8080', 'ACTIVATION_STATUS_CHANGE');