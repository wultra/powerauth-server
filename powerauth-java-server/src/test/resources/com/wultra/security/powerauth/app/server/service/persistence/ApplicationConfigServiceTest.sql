DELETE FROM pa_application_config WHERE application_id = 21;
DELETE FROM pa_application WHERE id = 21;

INSERT INTO pa_application (id, name) VALUES
    (21, 'PA_Tests');
