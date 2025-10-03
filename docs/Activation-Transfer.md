# Activation Transfer

PowerAuth server allows the transfer of existing activations.


## Activation Transfer Configuration

To enable activation transfer, an entry with the key `activation_transfer` must exist in the table `pa_application_config`.
This configuration is exposed to the Enrollment Server, and it will manifest itself in the response [Activation Spawn endpoint](https://developers.wultra.com/components/enrollment-server/develop/documentation/Mobile-Token-API#activation-spawn), issuing an activation code.

Mind that this table supports encryption, see [Encrypting Records in Database](./Encrypting-Records-in-Database.md) for details.


### Required Configuration

- `allowedTargetApplicationIds` - List of application IDs to which the activation is allowed to be transferred.
- `type` - Type of activation transfer, currently only `SPAWN` is supported.


### Example

The value of `config_values` column may look like this:

```json
[
  {
    "allowedTargetApplicationIds": [
      "application-1",
      "application-2"
    ],
    "type": "SPAWN"
  }
]
```
