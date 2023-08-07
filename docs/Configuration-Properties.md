# Configuration Properties

The PowerAuth Server uses the following public configuration properties:

## Database Configuration

| Property | Default | Note |
|---|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/powerauth` | Database JDBC URL |
| `spring.datasource.username` | `powerauth` | Database JDBC username |
| `spring.datasource.password` | `_empty_` | Database JDBC password |
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

| Property                                                      | Default   | Note                                                                                    |
|---------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------|
| `powerauth.service.crypto.activationValidityTime`   | `PT2M`  | Default activation validity period (ISO 8601 Duration format) |
| `powerauth.service.crypto.signatureMaxFailedAttempts`         | `5`       | Maximum failed attempts for signature verification                                      |
| `powerauth.service.token.timestamp.validity`                  | `PT2H` | PowerAuth MAC token timestamp validity (ISO 8601 Duration format) |
| `powerauth.service.recovery.maxFailedAttempts`                | `5`       | Maximum failed attempts for activation recovery                                         |
| `powerauth.service.secureVault.enableBiometricAuthentication` | `false`   | Whether biometric authentication is enabled when accessing Secure Vault                 |
| `powerauth.server.db.master.encryption.key`                   | `_empty_` | Master DB encryption key for decryption of server private key in database               |
| `powerauth.service.proximity-check.otp.length`                | `8`       | Length of OTP generated for proximity check                                             |
| `powerauth.service.pagination.default-page-size`              | `100`     | The default number of records per page when paginated results are requested             |
| `powerauth.service.pagination.default-page-number`            | `0`       | The default page number when paginated results are requested. Page numbers start from 0 |

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

## Correlation HTTP Header Configuration

| Property | Default | Note |
|---|---|---|
| `powerauth.service.correlation-header.enabled` | `false` | Whether correlation header is enabled |
| `powerauth.service.correlation-header.name` | `X-Correlation-ID` | Correlation header name |
| `powerauth.service.correlation-header.value.validation-regexp` | `[a-zA-Z0-9\\-]{8,1024}` | Regular expression for correlation header value validation |
| `logging.pattern.console` | [See value in application.properties](https://github.com/wultra/powerauth-server/blob/develop/powerauth-java-server/src/main/resources/application.properties#docucheck-keep-link) | Logging pattern for console which includes the correlation header value |
