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

### Add activation_id Column

Add a new column `activation_id` to the `pa_operation` table. This column is a foreign key that references
the `activation_id` column in the `pa_activation` table. Storing the `activation_id` in the `pa_operation` table
provides several enhancements:

* It allows the creation of a new operation tied to a specific mobile device, identified by its activation ID.
* It ensures that the operation can only be approved on that specific mobile device, again identified by its activation ID.

