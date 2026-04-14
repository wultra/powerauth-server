INSERT INTO pa_operation_template(id, template_name, operation_type, data_template, signature_type, max_failure_count, expiration, proximity_check_enabled) VALUES
    (1, 'login', 'login', 'A2', 'possession,knowledge,biometry,possession_knowledge,possession_biometry,possession_knowledge_biometry', 5, 300, false),
    (2, 'login_unsupported_signature_types_only', 'login', 'A2', 'knowledge,biometry,possession_knowledge_biometry', 5, 300, false);


