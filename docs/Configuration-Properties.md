# Configuration Properties

The PowerAuth Server uses the following public configuration properties:

## Database Configuration

| Property | Default | Note |
|---|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/powerauth` | Database JDBC URL |
| `spring.datasource.username` | `powerauth` | Database JDBC username |
| `spring.datasource.password` | `_empty_` | Database JDBC passwod |
| `spring.datasource.driver-class-name` | `org.postgresql.Driver` | Datasource JDBC class name | 
| `spring.jpa.database-platform` | `org.hibernate.dialect.PostgreSQLDialect` | Database dialect | 
| `spring.jpa.hibernate.ddl-auto` | `none` | Configuration of automatic database schema creation | 
| `spring.jpa.properties.hibernate.connection.characterEncoding` | `utf8` | Character encoding |
| `spring.jpa.properties.hibernate.connection.useUnicode` | `true` | Character encoding - Unicode support |

## PowerAuth Service Configuration

| Property | Default | Note |
|---|---|---|
| `powerauth.service.applicationName` | `powerauth-server` | Application name exposed in status endpoint |
| `powerauth.service.applicationDisplayName` | `PowerAuth Server` | Application display name exposed in status endpoint |
| `powerauth.service.applicationEnvironment` | `_empty_` | Application environment exposed in status endpoint |
| `powerauth.service.restrictAccess` | `false` | Whether access to the REST API is restricted |

## Activation and Cryptography Configuration

| Property | Default | Note |
|---|---|---|
| `powerauth.service.crypto.activationValidityInMilliseconds` | `120000` | Default activation validity period in miliseconds |
| `powerauth.service.crypto.signatureMaxFailedAttempts` | `5` | Maximum failed attempts for signature verification |
| `powerauth.service.token.timestamp.validity` | `7200000` |PowerAuth MAC token timestamp validity in miliseconds |
| `powerauth.service.recovery.maxFailedAttempts` | `5` | Maximum failed attempts for activation recovery |
| `powerauth.service.secureVault.enableBiometricAuthentication` | `false` | Whether biometric authentication is enabled when accessing Secure Vault |
| `powerauth.server.db.master.encryption.key` | `_empty_` | Master DB encryption key for decryption of server private key in database |

## HTTP Configuration
| Property | Default | Note |
|---|---|---|
| `powerauth.service.http.proxy.enabled` | `false` | Whether proxy is enabled for outgoing HTTP requests |
| `powerauth.service.http.proxy.host` | `127.0.0.1` | Proxy host for outgoing HTTP requests |
| `powerauth.service.http.proxy.port` | `8080` | Proxy port for outgoing HTTP requests |
| `powerauth.service.http.proxy.username` | `_emtpy_` | Proxy username for outgoing HTTP requests |
| `powerauth.service.http.proxy.password` | `_empty_` | Proxy password for outgoing HTTP requests |

## Spring Vault Configuration
| Property | Default | Note |
|---|---|---|
| `spring.cloud.vault.enabled` | `false` | Whether Spring Vault integration is enabled |
| `spring.cloud.vault.kv.enabled` | `true` | Whether the Spring Vault integration uses the versioned key-value backend |
