# Integrating with HashiCorp Vault

In order to protect the database records, PowerAuth has an embedded [mechanism for secret data encryption via a symmetric key](./Encrypting-Records-in-Database.md). The encryption key can be configured via setting the `powerauth.server.db.master.encryption.key` property in the `application.properties` file. However, to achieve better security of this key, you can also use a [HashiCorp Vault](https://www.hashicorp.com/products/vault/).

## About HashiCorp Vault

[HashiCorp Vault](https://www.hashicorp.com/products/vault/) (or just Vault, for short) is just like [HSM](https://en.wikipedia.org/wiki/Hardware_security_module), but in software. It is a convenient mechanism to store secret keys, passwords, or perform cryptographic operations in an isolated secure environment. It provides a convenient API-based interface (RESTful API) and extremely easy integration with Spring Boot apps via [Spring Cloud Vault](https://cloud.spring.io/spring-cloud-vault). Finally, the enterprise version of Vault supports integration with HSM for even better key protection.

## Installation and Setup

To install Vault, simply follow the [download and installation instruction on HashiCorp website](https://www.vaultproject.io/downloads.html). On Mac, you can install Vault easily by running:

```bash
$ brew install vault
```

The easiest way to start Vault for initial testing is by using the development mode with a "zero token", like so:

```bash
$ vault server --dev --dev-root-token-id="00000000-0000-0000-0000-000000000000"
```

The Vault starts rather quickly, the last message should be of a format:

```bash
2019-08-07T20:47:41.280+0200 [INFO]  secrets.kv.kv_3cfd3149: upgrading keys finished
```

Beware! Never use the "zero token" authentication mentioned above for production environment. Refer to the [Spring Cloud Vault documentation](https://cloud.spring.io/spring-cloud-vault) for more details.

After starting the Vault, you need to set two environment variables to point the Vault CLI to the Vault endpoint and to provide an authentication token:

```bash
$ export export VAULT_TOKEN="00000000-0000-0000-0000-000000000000"
$ export VAULT_ADDR="http://127.0.0.1:8200"
```

## Adding Database Encryption Key in the Vault

To add a key used to encrypt and decrypt sensitive records in the PowerAuth database, simply call the following command from the terminal:

```bash
$ vault kv put secret/powerauth-java-server powerauth.server.db.master.encryption.key=[16 bytes encoded in base64, for example 'MTIzNDU2Nzg5MDEyMzQ1Ng==']
```

Note the key name `secret/powerauth-java-server`. This is the default name of the secure bucket in Vault based on the value of `spring.application.name` property (that is set to `powerauth-java-server` by default). Adjust the name of this key in case you changed the value of `spring.application.name` property. Also, in case you use a custom configuration profile (for example, `testing`), you need to adjust the name by appending the profile name (for example, `secret/powerauth-java-server/testing`).

To check that the value is present in the Vault, you can use:

```bash
$ vault kv get secret/powerauth-java-server
```

## Configuring PowerAuth Server

In order to make the running PowerAuth Server aware of the running Vault instance and to configure Vault authentication, you need to set the following properties in `application.properties` (or `application.yml` file).

```properties
spring.cloud.vault.enabled=true
spring.cloud.vault.host=localhost
spring.cloud.vault.port=8200
spring.cloud.vault.scheme=http
spring.cloud.vault.authentication=TOKEN
spring.cloud.vault.token=00000000-0000-0000-0000-000000000000
```

<!-- begin box warning -->
Note: For production environment, make sure to use different authentication parameters than the one in the example above. Please refer to [Spring Cloud Vault documentation](https://cloud.spring.io/spring-cloud-vault) for more details.
<!-- end -->

In case you are using Apache Tomcat for deployment, you can set the properties via your `${CATALINA_HOME}/conf/Catalina/localhost/powerauth-java-server.xml` configuration file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>

    <!-- ... other configuration properties -->

    <Parameter name="spring.cloud.vault.enabled" value="true"/>
    <Parameter name="spring.cloud.vault.host" value="localhost"/>
    <Parameter name="spring.cloud.vault.port" value="8200"/>
    <Parameter name="spring.cloud.vault.scheme" value="http"/>
    <Parameter name="spring.cloud.vault.authentication" value="TOKEN"/>
    <Parameter name="spring.cloud.vault.token" value="00000000-0000-0000-0000-000000000000"/>

</Context>
```

After restarting the PowerAuth Server, the configuration of encryption key will be automatically picked up from the Vault instance configured in the properties.

<!-- begin box info -->
In case you set the `powerauth.server.db.master.encryption.key` property in your Tomcat XML configuration directly (in a plain text), the configuration from the Vault still has a precedence and will be used over the hardcoded encryption key value.
<!-- end -->
