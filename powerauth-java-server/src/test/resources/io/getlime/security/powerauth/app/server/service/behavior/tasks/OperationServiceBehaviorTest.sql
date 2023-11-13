INSERT INTO pa_operation_template (id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration, proximity_check_enabled)
VALUES (1, 'login', 'login', 'A2', 'POSSESSION_KNOWLEDGE', 5, 300, false);

INSERT INTO pa_application (id, name) VALUES
    (2, 'PA_Tests');