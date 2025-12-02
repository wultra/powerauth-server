# Integrating with HashiCorp Vault

To protect database records, PowerAuth provides an embedded mechanism for application-level encryption of sensitive data. The encryption key can be configured using the `powerauth.server.db.master.encryption.aead-kmac.key` property in the `application.properties` file. To improve the security of this master key, you can store it in a HashiCorp Vault instance.

## About HashiCorp Vault

HashiCorp Vault (or simply "Vault") is a software-based secure storage and cryptographic service. It can store secret keys, credentials, and certificates, and it can perform cryptographic operations in an isolated, policy-controlled environment. It exposes a REST API and integrates easily with Spring Boot applications through Spring Cloud Vault. The enterprise edition of Vault also supports HSM integration for hardware-backed master key protection.

## Installation and Setup

To install Vault, follow the official installation instructions:  
https://www.vaultproject.io/downloads

On macOS, you can install Vault using Homebrew:

```bash
brew install vault
```

For basic testing, you can start Vault in development mode:

```bash
vault server --dev --dev-root-token-id="00000000-0000-0000-0000-000000000000"
```

The server will start quickly and show a log entry similar to:

```bash
[INFO]  secrets.kv: upgrading keys finished
```

Warning: Never use development mode or the example token above in production. See the Spring Cloud Vault documentation for recommended authentication and deployment practices.

Before using the Vault CLI, configure environment variables:

```bash
export VAULT_TOKEN="00000000-0000-0000-0000-000000000000"
export VAULT_ADDR="http://127.0.0.1:8200"
```

## Adding the Database Encryption Key to Vault

To store the PowerAuth database encryption key inside Vault, run:

```bash
vault kv put secret/powerauth-java-server powerauth.server.db.master.encryption.aead-kmac.key=[32 bytes base64, for example 'mC92FrUKjMCqIKW5qVOduxRlBeEQ+fLsQjPxf1k9ow8=']
```

Notes:

- The `secret/powerauth-java-server` path corresponds to the application name specified by the `spring.application.name` property (default: `powerauth-java-server`).
- If you are using a Spring profile (for example `testing`), the effective path becomes:  
  `secret/powerauth-java-server/testing`
- The key must be exactly 32 random bytes, Base64-encoded.

To verify the stored value:

```bash
vault kv get secret/powerauth-java-server
```

## Configuring PowerAuth Server

To connect PowerAuth Server to Vault and configure authentication, add the following properties to `application.properties` or `application.yml`:

```properties
spring.cloud.vault.enabled=true
spring.cloud.vault.host=localhost
spring.cloud.vault.port=8200
spring.cloud.vault.scheme=http
spring.cloud.vault.authentication=TOKEN
spring.cloud.vault.token=00000000-0000-0000-0000-000000000000
spring.cloud.vault.kv.enabled=true
spring.cloud.vault.kv.backend=secret
spring.cloud.vault.kv.default-context=powerauth-java-server
```

Note: Do not use development-mode authentication or example tokens in production.

### Deployment on Apache Tomcat

If deploying under Apache Tomcat, you may include these properties inside `${CATALINA_HOME}/conf/Catalina/localhost/powerauth-java-server.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>

    <!-- Other configuration properties -->

    <Parameter name="spring.cloud.vault.enabled" value="true"/>
    <Parameter name="spring.cloud.vault.host" value="localhost"/>
    <Parameter name="spring.cloud.vault.port" value="8200"/>
    <Parameter name="spring.cloud.vault.scheme" value="http"/>
    <Parameter name="spring.cloud.vault.authentication" value="TOKEN"/>
    <Parameter name="spring.cloud.vault.token" value="00000000-0000-0000-0000-000000000000"/>
    <Parameter name="spring.cloud.vault.kv.enabled" value="true"/>
    <Parameter name="spring.cloud.vault.kv.backend" value="secret"/>
    <Parameter name="spring.cloud.vault.kv.default-context" value="powerauth-java-server"/>

</Context>
```

After restarting the PowerAuth Server, the encryption key will be automatically loaded from the configured Vault instance.

Note: If you set the `powerauth.server.db.master.encryption.aead-kmac.key` property directly in your Tomcat XML configuration, the value from Vault will still take precedence and override the plaintext configuration.
