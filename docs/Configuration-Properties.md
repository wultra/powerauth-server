# Configuration Properties

The PowerAuth Server uses the following public configuration properties:

## Database Configuration

| Property | Default | Note |
|---|---|---|
| `spring.datasource.url` | `jdbc:postgresql://localhost:5432/powerauth` | Database JDBC URL |
| `spring.datasource.username` | `powerauth` | Database JDBC username |
| `spring.datasource.password` | `_empty_` | Database JDBC password |
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

| Property                                                           | Default   | Note                                                                                    |
|--------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------|
| `powerauth.service.crypto.activationValidityInMilliseconds`        | `120000`  | Default activation validity period in miliseconds                                       |
| `powerauth.service.crypto.signatureMaxFailedAttempts`              | `5`       | Maximum failed attempts for signature verification                                      |
| `powerauth.service.crypto.requestExpirationInMilliseconds`         | `60000`   | Expiration for ECIES and MAC token requests.                                            |
| `powerauth.service.crypto.requestExpirationInMillisecondsExtended` | `7200000` | Expiration for ECIES and MAC token requests for protocol versions 3.1 and older.        |
| `powerauth.service.crypto.replayVerificationService`               | `default` | Request replay verification service, options: `default`, `none`                         |
| `powerauth.service.token.timestamp.validity`                       | `7200000` | PowerAuth MAC token timestamp validity in miliseconds                                   |
| `powerauth.service.recovery.maxFailedAttempts`                     | `5`       | Maximum failed attempts for activation recovery                                         |
| `powerauth.service.secureVault.enableBiometricAuthentication`      | `false`   | Whether biometric authentication is enabled when accessing Secure Vault                 |
| `powerauth.server.db.master.encryption.key`                        | `_empty_` | Master DB encryption key for decryption of server private key in database               |
| `powerauth.service.proximity-check.otp.length`                     | `8`       | Length of OTP generated for proximity check                                             |
| `powerauth.service.pagination.default-page-size`                   | `500`     | The default number of records per page when paginated results are requested             |
| `powerauth.service.pagination.default-page-number`                 | `0`       | The default page number when paginated results are requested. Page numbers start from 0 |

## HTTP Configuration

| Property                                          | Default     | Note                                                |
|---------------------------------------------------|-------------|-----------------------------------------------------|
| `powerauth.service.http.proxy.enabled`            | `false`     | Whether proxy is enabled for outgoing HTTP requests |
| `powerauth.service.http.proxy.host`               | `127.0.0.1` | Proxy host for outgoing HTTP requests               |
| `powerauth.service.http.proxy.port`               | `8080`      | Proxy port for outgoing HTTP requests               |
| `powerauth.service.http.proxy.username`           | `_emtpy_`   | Proxy username for outgoing HTTP requests           |
| `powerauth.service.http.proxy.password`           | `_empty_`   | Proxy password for outgoing HTTP requests           |
| `powerauth.service.http.connection.timeout`       | `5s`        | HTTP connection timeout                             |
| `powerauth.service.http.response.timeout`         | `60s`       | HTTP response timeout                               |
| `powerauth.service.http.connection.max-idle-time` | `200s`      | HTTP max idle time                                  |

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


## Monitoring and Observability

| Property                                  | Default | Note                                                                                                                                                                        |
|-------------------------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `management.tracing.sampling.probability` | `1.0`   | Specifies the proportion of requests that are sampled for tracing. A value of 1.0 means that 100% of requests are sampled, while a value of 0 effectively disables tracing. |

The WAR file includes the `micrometer-registry-prometheus` dependency.
Discuss its configuration with the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/3.1.x/reference/html/actuator.html#actuator.metrics).

## Scheduled Jobs Configuration

| Property                                                                    | Default         | Note                                                                                                                                                                   |
|-----------------------------------------------------------------------------|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `powerauth.service.scheduled.job.operationCleanup`                          | `5000`          | Time delay in milliseconds between two consecutive tasks that expire long pending operations.                                                                          |
| `powerauth.service.scheduled.job.expireOperationsLimit`                     | `100`           | Number of long pending operations that will be set expired in single scheduled job run.                                                                                |
| `powerauth.service.scheduled.job.activationsCleanup`                        | `5000`          | Time delay in milliseconds between two consecutive tasks that expire abandoned activations.                                                                            |
| `powerauth.service.scheduled.job.activationsCleanup.lookBackInMilliseconds` | `3600000`       | Number of milliseconds to look back in the past when looking for abandoned activations.                                                                                |
| `powerauth.service.scheduled.job.uniqueValueCleanup`                        | `60000`         | Time delay in milliseconds between two consecutive tasks that delete expired unique values.                                                                            |
| `powerauth.service.scheduled.job.retryFailedCallbackUrlEvent`               | `3000`          | Time delay in milliseconds between two consecutive tasks that try to send again failed callback events.                                                                |
| `powerauth.service.scheduled.job.dispatchPendingCallbackUrlEvent`           | `3000`          | Time delay in milliseconds between two consecutive tasks that try to send pending callback events that could not be dispatched immediately by callback event listener. |
| `powerauth.service.scheduled.job.callbackUrlEventsCleanupCron`              | `0 0 0 */3 * *` | Cron schedule triggering a task to clean callback events after their retention period has expired.                                                                     |
| `powerauth.service.scheduled.job.fido2AuthenticatorCacheEviction`           | `3600000`       | Duration in milliseconds for which the internal cache holds details of FIDO2 Authenticator models.                                                                     |

## Callback URL Events Configuration

PowerAuth monitors status of operations and activations. When their status changes, configured callbacks are triggered.
The following properties allow you to configure the maximum number of attempts and the exponential backoff algorithm
for dispatching a callback event. The default values are set with respect to the behavior of previous PowerAuth version.
However, it is possible to override these defaults or configure each callback settings individually using the
Callback URL Management API.

PowerAuth dispatches a callback as soon as a change in operation or activation status is detected. This is achieved
through a callback event listener that uses a configurable thread pool. Even if the thread pool's queue is currently
full, the callback will eventually be dispatched.

| Property                                                        | Default | Note                                                                                                  |
|-----------------------------------------------------------------|---------|-------------------------------------------------------------------------------------------------------|
| `powerauth.service.callbacks.defaultMaxAttempts`                | `1`     | Default maximum number of dispatch attempts for a callback event.                                     |
| `powerauth.service.callbacks.defaultRetentionPeriod`            | `30d`   | Default retention period of a callback event before deleting its record from the database table.      |
| `powerauth.service.callbacks.defaultInitialBackoffMilliseconds` | `2000`  | Default initial backoff between successive attempts of dispatching a callback event.                  |
| `powerauth.service.callbacks.maxBackoffMilliseconds`            | `32000` | The maximum allowable backoff period between successive attempts to dispatch a callback event.        |
| `powerauth.service.callbacks.backoffMultiplier`                 | `1.5`   | The multiplier used to calculate the backoff period.                                                  |
| `powerauth.service.callbacks.failedCallbackUrlEventsRetryLimit` | `100`   | Maximum number of failed callback events that will be dispatched again in a single scheduled job run. |
| `powerauth.service.callbacks.threadPoolCoreSize`                | `1`     | Number of core threads in the thread pool used by listener of new callback events.                    |
| `powerauth.service.callbacks.threadPoolMaxSize`                 | `2`     | Maximum number of threads in the thread pool used by listener of new callback events.                 |
| `powerauth.service.callbacks.threadPoolQueueCapacity`           | `1000`  | Queue capacity of the thread pool used by listener of new callback events.                            |

The backoff period after the `N-th` attempt is calculated as follows:

```
exponentialBackoff = initialBackoff * backoffMultiplier^(N-1)
backoffPeriod = min(exponentialBackoff, maxBackoff)
```
