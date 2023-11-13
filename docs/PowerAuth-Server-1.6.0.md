# Migration from 1.5.x to 1.6.0

This guide contains instructions for migration from PowerAuth Server version `1.5.x` to version `1.6.0`.

## Database Changes

### Forbid name duplication for operation templates.

Add unique constraint to `templateName` column in `pa_operation_template` table.

Applying this change may fail if there are duplicates in the `pa_operation_template` table. Please make sure there are
no two records with the same name `templateName`. If necessary, remove any duplicities from the table manually. Consider
creating a backup before this operation.

### Add foreign key constraints to operations and applications relation.

Add foreign key constraints to relating table `pa_operation_application`.

Applying this change may fail if there is an inconsistency between tables `pa_operation_application`
and `pa_application` or `pa_operation`. Make sure that `pa_operation_application.application_id` contains references to
existing `pa_application.id` and `pa_operation_application.operation_id` contains references to
existing `pa_operation.id`. If necessary, manually remove orphaned records in `pa_operation_application`. Consider
creating a backup before this operation.

### Add application_id column

Add new column `application_id` to `pa_operation` table. Storing `application_id` brings enhancements for developers:

* Create a new operation on a specific mobile device (activation ID).
* Approve the operation just on that specific mobile device (activation ID).
