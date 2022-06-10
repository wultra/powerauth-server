# Configuration of Activation Recovery

PowerAuth Server supports activation recovery in case user loses mobile device or it gets stolen. Activation recovery
can be enabled using PowerAuth Admin.

## Enabling Activation Recovery

By default activation recovery is disabled, which means that if the user loses the mobile device a new activation needs
to be created.

Activation recovery allows recovering the activation using a recovery code and recovery PUK without going through
the complicated activation process.

The activation recovery is described in details in [Activation Recovery documentation](https://github.com/wultra/powerauth-crypto/develop/docs/Activation-Recovery.md).

There are two types of activation recovery:
1. [Activation recovery for activations](./Activation-Recovery.md#enabling-activation-recovery-for-activations)
1. [Activation recovery using recovery postcard](./Activation-Recovery.md#enabling-activation-recovery-using-recovery-postcard)

### Enabling Activation Recovery for Activations

You can enable Activation Recovery for Activations using following steps in PowerAuth Admin:

- Find the Application you want to configure using `Applications` tab.
- Navigate to the `Recovery Settings` tab.
- Enable the `Activation Recovery Enabled` checkbox

From now on the PowerAuth Server will generate recovery codes and PUKs for new activations. Users will be asked
to write down the recovery code and PUK during an activation and they can use these details to recover an activation
later on.

### Enabling Activation Recovery using Recovery Postcard

You can enable Activation Recovery using Recovery Postcard using following steps in PowerAuth Admin:

- Find the Application you want to configure using `Applications` tab.
- Navigate to the `Recovery Settings` tab.
- Enable the `Activation Recovery Enabled` checkbox (should be already enabled, see chapter [Enabling Activation Recovery for Activations](./Activation-Recovery.md#enabling-activation-recovery-for-activations))
- Enabled the `Recovery Postcard Enabled` checkbox

The `Recovery Postcard Public Key` value contains public key for key exchange with Recovery Postcard printing center which represents PowerAuth server.
This key needs to be entered into the Recovery Postcard Printing Center application and it enables secure sharing of recovery code and PUK data.

You need to configure the `Recovery Postcard Printing Center Public Key` which represents the Recovery Postcard printing center.
This key is provided by the Recovery Postcard Printing Center application and is also required for secure sharing of recovery code and PUK  data.

The checkbox `Allow Multiple Recovery Codes for User` is used to configure whether existing recovery codes for the user need to be revoked before 
creating another recovery code. In case the checkbox is enabled, it is not necessary to revoke existing codes and multiple recovery postcards can exist.
Otherwise revoking recovery code is necessary before creating a new recovery code.

Once activation recovery using recovery postcard is configured it is possible to create recovery postcards with
recovery codes and PUKs and distribute them securely to users.
 