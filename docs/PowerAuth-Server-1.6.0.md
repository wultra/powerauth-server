# Migration from 1.5.x to 1.6.0

This guide contains instructions for migration from PowerAuth Server version `1.5.x` to version `1.6.0`.

## Database Changes

### Forbid name duplication for operation templates.

Add unique constraint to `templateName` column in `pa_operation_template` table.

### Add foreign key constraints to operations and applications relation.

Add foreign key constraints to relating table `pa_operation_application`.
