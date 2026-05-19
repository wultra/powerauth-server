DELETE FROM pa_application_config WHERE application_id = 21;

MERGE INTO pa_application (id, name) KEY(id) VALUES
    (21, 'PA_Tests');
