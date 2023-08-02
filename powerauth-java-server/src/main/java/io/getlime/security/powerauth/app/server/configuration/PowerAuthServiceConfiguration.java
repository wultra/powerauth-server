/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.getlime.security.powerauth.app.server.configuration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.time.format.DateTimeParseException;

/**
 * Class holding the configuration data of this PowerAuth Server
 * instance. Default values are in "application.properties" file.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
@ConfigurationProperties("ext")
@Validated
public class PowerAuthServiceConfiguration {

    /**
     * Minimal value for {@link #proximityCheckOtpLength}.
     */
    private static final int MINIMAL_PROXIMITY_CHECK_OTP_LENGTH = 6;

    /**
     * When asking for server status, this variable will be returned as application
     * name.
     */
    @Value("${powerauth.service.applicationName}")
    private String applicationName;

    /**
     * When asking for server status, this variable will be returned as application
     * display name.
     */
    @Value("${powerauth.service.applicationDisplayName}")
    private String applicationDisplayName;

    /**
     * When asking for server status, this variable will be returned as application
     * system environment (for example, 'dev' or 'prod').
     */
    @Value("${powerauth.service.applicationEnvironment}")
    private String applicationEnvironment;

    /**
     * If this variable is set to true, server will check credentials client uses
     * to access the service and compare them with credentials stored in 'pa_integration'
     * table.
     */
    @Value("${powerauth.service.restrictAccess}")
    private Boolean restrictAccess;

    /**
     * When a duplicate activation ID is encountered during the activation, how
     * many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateActivationIdIterations}")
    @Min(1)
    private int activationGenerateActivationIdIterations;

    /**
     * When a duplicate token ID is encountered during the token generation, how
     * many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateTokenIdIterations}")
    @Min(1)
    private int generateTokenIdIterations;

    /**
     * When a duplicate activation code is encountered during the
     * activation, how many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateActivationCodeIterations}")
    @Min(1)
    private int activationGenerateActivationCodeIterations;

    /**
     * When a duplicate recovery code is encountered, how many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateRecoveryCodeIterations}")
    @Min(1)
    private int generateRecoveryCodeIterations;

    /**
     * When a duplicate operation ID is encountered, how many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateOperationIterations}")
    @Min(1)
    private int generateOperationIterations;

    /**
     * Specifies the duration for which a CREATED or PENDING_COMMIT record should remain usable for
     * completing the activation.
     * <p>
     * The value must be specified in the ISO-8601 duration format PTnHnMn.nS.
     */
    @Value("${powerauth.service.crypto.activationValidityTime}")
    @DurationMin(millis = 0)
    private Duration activationValidityBeforeActive;

    /**
     * Specifies the duration to the past that the activation cleanup job should look at.
     * <p>
     * The value must be specified in the ISO-8601 duration format PTnHnMn.nS.
     */
    @Value("${powerauth.service.scheduled.job.activationsCleanup.lookBack:PT1H}")
    @DurationMin(millis = 0)
    private Duration activationsCleanupLookBack;

    /**
     * How many failed signatures cause activation record blocking. The maximum supported value is 64.
     */
    @Value("${powerauth.service.crypto.signatureMaxFailedAttempts}")
    @Min(0)
    @Max(64)
    private long signatureMaxFailedAttempts;

    /**
     * When validating the signature, how many iterations ahead to look in case signature fails for the first
     * counter value. The maximum supported value is 64.
     */
    @Value("${powerauth.service.crypto.signatureValidationLookahead}")
    @Min(1)
    @Max(64)
    private long signatureValidationLookahead;

    /**
     * When validating the offline (or decimalized) signature, how many digits should a factor-related component have.
     */
    @Value("${powerauth.service.crypto.offlineSignatureComponentLength}")
    @Min(4)
    @Max(8)
    private int offlineSignatureComponentLength;

    /**
     * Specifies the expiration duration for timestamps used in ECIES and MAC token requests.
     * <p>
     * The value is specified in the ISO-8601 duration format PTnHnMn.nS.
     */
    @Value("${powerauth.service.crypto.requestExpirationTime}")
    @DurationMin(millis = 0)
    private Duration requestExpiration;

    /**
     * Whether HTTP proxy is enabled for outgoing HTTP requests.
     */
    @Value("${powerauth.service.http.proxy.enabled}")
    private Boolean httpProxyEnabled;

    /**
     * HTTP proxy host.
     */
    @Value("${powerauth.service.http.proxy.host}")
    private String httpProxyHost;

    /**
     * HTTP proxy port.
     */
    @Value("${powerauth.service.http.proxy.port}")
    private Integer httpProxyPort;

    /**
     * HTTP proxy username, use only in case HTTP proxy authentication is required.
     */
    @Value("${powerauth.service.http.proxy.username}")
    private String httpProxyUsername;

    /**
     * HTTP proxy password, use only in case HTTP proxy authentication is required.
     */
    @Value("${powerauth.service.http.proxy.password}")
    private String httpProxyPassword;

    /**
     * HTTP connection timeout.
     */
    @Value("${powerauth.service.http.connection.timeout}")
    private Duration httpConnectionTimeout;

    /**
     * Specifies the validity duration of token timestamps, checked before token validation.
     * <p>
     * The value is specified in the ISO-8601 duration format PTnHnMn.nS.
     */
    @Value("${powerauth.service.token.timestamp.validity}")
    @DurationMin(millis = 1)
    private Duration tokenTimestampValidity;

    /**
     * Specifies the validity duration to future of token timestamps, checked before token validation.
     * <p>
     * The value is specified in the ISO-8601 duration format PTnHnMn.nS.
     */
    @Value("${powerauth.service.token.timestamp.forward.validity}")
    @DurationMin(millis = 0)
    private Duration tokenTimestampForwardValidity;


    /**
     * Master DB encryption key.
     */
    @Value("${powerauth.server.db.master.encryption.key}")
    private String masterDbEncryptionKey;

    /**
     * How many failed usages of recovery code block the recovery code. The maximum supported value is 64.
     */
    @Value("${powerauth.service.recovery.maxFailedAttempts}")
    @Min(0)
    @Max(64)
    private long recoveryMaxFailedAttempts;

    /**
     * If enabled, then the vault encryption key can be acquired also after the successful biometric authentication.
     */
    @Value("${powerauth.service.secureVault.enableBiometricAuthentication}")
    private boolean secureVaultBiometricAuthenticationEnabled;

    /**
     * Length of OTP generated for proximity check.
     */
    @Value("${powerauth.service.proximity-check.otp.length:8}")
    private int proximityCheckOtpLength;

    /**
     * Prepare and configure object mapper.
     * @return Object mapper.
     */
    @Bean
    public ObjectMapper objectMapper() {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        objectMapper.registerModule(new JavaTimeModule());
        return objectMapper;
    }

    /**
     * Get application name, usually used as a "unique code" for the application within
     * a server infrastructure.
     *
     * @return Application name.
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Set application name.
     *
     * @param applicationName Application name.
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Get application display name, usually used as a "visual representation" of the
     * application within a server infrastructure.
     *
     * @return Application display name.
     */
    public String getApplicationDisplayName() {
        return applicationDisplayName;
    }

    /**
     * Set application display name.
     *
     * @param applicationDisplayName Application display name.
     */
    public void setApplicationDisplayName(String applicationDisplayName) {
        this.applicationDisplayName = applicationDisplayName;
    }

    /**
     * Get the application environment name.
     *
     * @return Application environment name.
     */
    public String getApplicationEnvironment() {
        return applicationEnvironment;
    }

    /**
     * Set the application environment name.
     *
     * @param applicationEnvironment Application environment name.
     */
    public void setApplicationEnvironment(String applicationEnvironment) {
        this.applicationEnvironment = applicationEnvironment;
    }

    /**
     * Get the value of a flag that indicates that access to the PA2.0 Server should be restricted
     * to predefined integrations.
     *
     * @return Flag with access restriction information.
     */
    public Boolean getRestrictAccess() {
        return restrictAccess;
    }

    /**
     * Set the value of a flag that indicates that access to the PA2.0 Server should be restricted
     * to predefined integrations.
     *
     * @param restrictAccess Flag with access restriction information.
     */
    public void setRestrictAccess(Boolean restrictAccess) {
        this.restrictAccess = restrictAccess;
    }

    /**
     * Get number of activation ID generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getActivationGenerateActivationIdIterations() {
        return activationGenerateActivationIdIterations;
    }

    /**
     * Set number of activation ID generation attempts in case of collision.
     * @param activationGenerateActivationIdIterations Retry iteration count (10, by default).
     */
    public void setActivationGenerateActivationIdIterations(int activationGenerateActivationIdIterations) {
        this.activationGenerateActivationIdIterations = activationGenerateActivationIdIterations;
    }

    /**
     * Get number of token ID generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getGenerateTokenIdIterations() {
        return generateTokenIdIterations;
    }

    /**
     * Set number of token ID generation attempts in case of collision.
     * @param generateTokenIdIterations Retry iteration count (10, by default).
     */
    public void setGenerateTokenIdIterations(int generateTokenIdIterations) {
        this.generateTokenIdIterations = generateTokenIdIterations;
    }

    /**
     * Get number of activation code generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getActivationGenerateActivationCodeIterations() {
        return activationGenerateActivationCodeIterations;
    }

    /**
     * Set number of activation code generation attempts in case of collision.
     * @param activationGenerateActivationCodeIterations Retry iteration count (10, by default).
     */
    public void setActivationGenerateActivationCodeIterations(int activationGenerateActivationCodeIterations) {
        this.activationGenerateActivationCodeIterations = activationGenerateActivationCodeIterations;
    }

    /**
     * Get number of recovery code generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getGenerateRecoveryCodeIterations() {
        return generateRecoveryCodeIterations;
    }

    /**
     * Set number of recovery code generation attempts in case of collision.
     * @param generateRecoveryCodeIterations Retry iteration count (10, by default).
     */
    public void setGenerateRecoveryCodeIterations(int generateRecoveryCodeIterations) {
        this.generateRecoveryCodeIterations = generateRecoveryCodeIterations;
    }

    /**
     * Get number of operation ID generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getGenerateOperationIterations() {
        return generateOperationIterations;
    }

    /**
     * Set number of operation ID generation attempts in case of collision.
     * @param generateOperationIterations Retry iteration count (10, by default).
     */
    public void setGenerateOperationIterations(int generateOperationIterations) {
        this.generateOperationIterations = generateOperationIterations;
    }

    /**
     * Get default number of maximum failed attempts.
     * @return Maximum failed attempts (5, by default).
     */
    public long getSignatureMaxFailedAttempts() {
        return signatureMaxFailedAttempts;
    }

    /**
     * Set default number of maximum failed attempts.
     * @param signatureMaxFailedAttempts Maximum failed attempts (5, by default).
     */
    public void setSignatureMaxFailedAttempts(long signatureMaxFailedAttempts) {
        this.signatureMaxFailedAttempts = signatureMaxFailedAttempts;
    }

    /**
     * Gets the length of the period of activation record validity during activation.
     * @return How long the activation is valid before it becomes active, represented as a {@link Duration}
     * (2 minutes, by default).
     */
    public Duration getActivationValidityBeforeActive() {
        return activationValidityBeforeActive;
    }


    /**
     * Sets the activation validity period before active as a {@link Duration}.
     * This is the maximum amount of time an activation is valid before it becomes active.
     *
     * @param activationValidityBeforeActive activation validity period as a {@link Duration}
     */
    public void setActivationValidityBeforeActive(Duration activationValidityBeforeActive) {
        this.activationValidityBeforeActive = activationValidityBeforeActive;
    }

    /**
     * Sets the activation validity period before active as an ISO-8601 duration string.
     * This is the maximum amount of time an activation is valid before it becomes active.
     * The string should be formatted according to the ISO-8601 duration format specification, e.g. "PT2M" for two minutes.
     *
     * @param activationValidityBeforeActive activation validity period as an ISO-8601 duration string
     */
    public void setActivationValidityBeforeActive(String activationValidityBeforeActive) {
        this.activationValidityBeforeActive = Duration.parse(activationValidityBeforeActive);
    }

    /**
     * Get the look-back period for the activation cleanup job.
     * @return The period of time the activation cleanup job should look into the past, represented as a {@link Duration}.
     * This value indicates how far back in time the cleanup job should look for activations to clean up
     * (1 hour, by default).
     */
    public Duration getActivationsCleanupLookBack() {
        return activationsCleanupLookBack;
    }


    /**
     * Sets the cleanup look back time for activations as a {@link Duration}.
     * This is the maximum amount of time to look back when cleaning up activations.
     *
     * @param activationsCleanupLookBack cleanup look back time as a {@link Duration}
     */
    public void setActivationsCleanupLookBack(Duration activationsCleanupLookBack) {
        this.activationsCleanupLookBack = activationsCleanupLookBack;
    }

    /**
     * Sets the cleanup look back time for activations as an ISO-8601 duration string.
     * This is the maximum amount of time to look back when cleaning up activations.
     * The string should be formatted according to the ISO-8601 duration format specification, e.g. "PT1H" for one hour.
     *
     * @param activationsCleanupLookBack cleanup look back time as an ISO-8601 duration string
     */
    public void setActivationsCleanupLookBack(String activationsCleanupLookBack) {
        this.activationsCleanupLookBack = Duration.parse(activationsCleanupLookBack);
    }


    /**
     * Get the signature validation lookahead.
     * @return Signature validation lookahead.
     */
    public long getSignatureValidationLookahead() {
        return signatureValidationLookahead;
    }

    /**
     * Set the signature validation lookahead.
     * @param signatureValidationLookahead Signature validation lookahead.
     */
    public void setSignatureValidationLookahead(long signatureValidationLookahead) {
        this.signatureValidationLookahead = signatureValidationLookahead;
    }

    /**
     * Get offline signature factor-related component length.
     * @return Factor-related component length.
     */
    public int getOfflineSignatureComponentLength() {
        return offlineSignatureComponentLength;
    }

    /**
     * Set offline signature factor-related component length.
     * @param offlineSignatureComponentLength Factor-related component length.
     */
    public void setOfflineSignatureComponentLength(int offlineSignatureComponentLength) {
        this.offlineSignatureComponentLength = offlineSignatureComponentLength;
    }

    /**
     * Gets the ECIES request expiration.
     * @return The ECIES request expiration, represented as a {@link Duration} (2 hours, by default).
     */
    public Duration getRequestExpiration() {
        return requestExpiration;
    }

    /**
     * Sets the ECIES request expiration.
     * @param requestExpiration The ECIES request expiration, represented as a {@link Duration}.
     */
    public void setRequestExpiration(Duration requestExpiration) {
        this.requestExpiration = requestExpiration;
    }

    /**
     * Sets the ECIES request expiration.
     * @param requestExpiration The ECIES request expiration, represented as a string in ISO-8601 duration format.
     * @throws DateTimeParseException if the string cannot be parsed to a Duration.
     */
    public void setRequestExpiration(String requestExpiration) {
        this.requestExpiration = Duration.parse(requestExpiration);
    }

    /**
     * Get whether HTTP proxy is enabled.
     * @return Whether HTTP proxy is enabled.
     */
    public Boolean getHttpProxyEnabled() {
        return httpProxyEnabled;
    }

    /**
     * Set whether HTTP proxy is enabled.
     * @param httpProxyEnabled Whether HTTP proxy is enabled.
     */
    public void setHttpProxyEnabled(Boolean httpProxyEnabled) {
        this.httpProxyEnabled = httpProxyEnabled;
    }

    /**
     * Get HTTP proxy host.
     * @return HTTP proxy host.
     */
    public String getHttpProxyHost() {
        return httpProxyHost;
    }

    /**
     * Set HTTP proxy host.
     * @param httpProxyHost HTTP proxy host.
     */
    public void setHttpProxyHost(String httpProxyHost) {
        this.httpProxyHost = httpProxyHost;
    }

    /**
     * Get HTTP proxy port.
     * @return HTTP proxy port.
     */
    public Integer getHttpProxyPort() {
        return httpProxyPort;
    }

    /**
     * Set HTTP proxy port.
     * @param httpProxyPort HTTP proxy port.
     */
    public void setHttpProxyPort(Integer httpProxyPort) {
        this.httpProxyPort = httpProxyPort;
    }

    /**
     * Get HTTP proxy username.
     * @return HTTP proxy username.
     */
    public String getHttpProxyUsername() {
        return httpProxyUsername;
    }

    /**
     * Set HTTP proxy username.
     * @param httpProxyUsername HTTP proxy username.
     */
    public void setHttpProxyUsername(String httpProxyUsername) {
        this.httpProxyUsername = httpProxyUsername;
    }

    /**
     * Get HTTP proxy password.
     * @return HTTP proxy password.
     */
    public String getHttpProxyPassword() {
        return httpProxyPassword;
    }

    /**
     * Set HTTP proxy password.
     * @param httpProxyPassword HTTP proxy password.
     */
    public void setHttpProxyPassword(String httpProxyPassword) {
        this.httpProxyPassword = httpProxyPassword;
    }

    /**
     * Gets the HTTP connection timeout.
     * @return The maximum duration of time to wait for an HTTP connection, represented as a {@link Duration}
     * (5 seconds, by default).
     */
    public Duration getHttpConnectionTimeout() {
        return httpConnectionTimeout;
    }

    /**
     * Set HTTP connection timeout.
     *
     * @param httpConnectionTimeout HTTP connection timeout, represented as a {@link Duration}.
     */
    public void setHttpConnectionTimeout(Duration httpConnectionTimeout) {
        this.httpConnectionTimeout = httpConnectionTimeout;
    }

    /**
     * Set HTTP connection timeout.
     *
     * @param httpConnectionTimeout HTTP connection timeout, represented as a string in ISO-8601 duration format.
     * @throws DateTimeParseException if the string cannot be parsed to a Duration.
     */
    public void setHttpConnectionTimeout(String httpConnectionTimeout) {
        this.httpConnectionTimeout = Duration.parse(httpConnectionTimeout);
    }

    /**
     * Gets the token timestamp validity.
     * @return The validity period of the token timestamp, represented as a {@link Duration} (2 hours, by default).
     */
    public Duration getTokenTimestampValidity() {
        return tokenTimestampValidity;
    }

    /**
     * Sets the token timestamp validity using a {@link Duration} object.
     * @param tokenTimestampValidity The validity period of the token timestamp, represented as a {@link Duration}.
     */
    public void setTokenTimestampValidity(Duration tokenTimestampValidity) {
        this.tokenTimestampValidity = tokenTimestampValidity;
    }

    /**
     * Sets the token timestamp validity using a string in the ISO-8601 duration format.
     * @param tokenTimestampValidity Token timestamp validity, represented as a string in ISO-8601 duration format.
     * @throws DateTimeParseException if the string cannot be parsed to a Duration.
     */
    public void setTokenTimestampValidity(String tokenTimestampValidity) {
        this.tokenTimestampValidity = Duration.parse(tokenTimestampValidity);
    }


    /**
     * Gets the token timestamp forward validity.
     * @return The validity period of the token timestamp into the future, represented as a {@link Duration}
     * (30 minutes, by default).
     */
    public Duration getTokenTimestampForwardValidity() {
        return tokenTimestampForwardValidity;
    }

    /**
     * Sets the token timestamp forward validity using a {@link Duration} object.
     * @param tokenTimestampForwardValidity The validity period of the token timestamp into the future,
     * represented as a Duration.
     */
    public void setTokenTimestampForwardValidity(Duration tokenTimestampForwardValidity) {
        this.tokenTimestampForwardValidity = tokenTimestampForwardValidity;
    }

    /**
     * Sets the token timestamp forward validity using a string in the ISO-8601 duration format.
     * @param tokenTimestampForwardValidity Token timestamp forward validity, represented as a string
     * in ISO-8601 duration format.
     * @throws DateTimeParseException if the string cannot be parsed to a Duration.
     */
    public void setTokenTimestampForwardValidity(String tokenTimestampForwardValidity) {
        this.tokenTimestampForwardValidity = Duration.parse(tokenTimestampForwardValidity);
    }


    /**
     * Get master DB encryption key.
     * @return Master DB encryption key.
     */
    public String getMasterDbEncryptionKey() {
        return masterDbEncryptionKey;
    }

    /**
     * Set master DB encryption key.
     * @param masterDbEncryptionKey Master DB encryption key.
     */
    public void setMasterDbEncryptionKey(String masterDbEncryptionKey) {
        this.masterDbEncryptionKey = masterDbEncryptionKey;
    }

    /**
     * Get default number of maximum failed attempts for recovery codes.
     * @return Maximum failed attempts for recovery codes (5, by default).
     */
    public long getRecoveryMaxFailedAttempts() {
        return recoveryMaxFailedAttempts;
    }

    /**
     * Set default number of maximum failed attempts for recovery codes.
     * @param recoveryMaxFailedAttempts Maximum failed attempts for recovery codes (5, by default).
     */
    public void setRecoveryMaxFailedAttempts(long recoveryMaxFailedAttempts) {
        this.recoveryMaxFailedAttempts = recoveryMaxFailedAttempts;
    }

    /**
     * Get whether vault encryption key can be acquired also after the successful biometric authentication.
     * @return {@code true} if vault encryption key can be acquired also after the successful biometric authentication.
     */
    public boolean isSecureVaultBiometricAuthenticationEnabled() {
        return secureVaultBiometricAuthenticationEnabled;
    }

    /**
     * Set whether vault encryption key can be acquired also after the successful biometric authentication.
     * @param secureVaultBiometricAuthenticationEnabled If {@code true}, then vault encryption key can be acquired
     *                                                  also after the successful biometric authentication.
     */
    public void setSecureVaultBiometricAuthenticationEnabled(boolean secureVaultBiometricAuthenticationEnabled) {
        this.secureVaultBiometricAuthenticationEnabled = secureVaultBiometricAuthenticationEnabled;
    }

    /**
     * Get length of OTP generated for proximity check.
     *
     * @return length of OTP
     */
    public int getProximityCheckOtpLength() {
        return proximityCheckOtpLength;
    }

    /**
     * Set length of OTP generated for proximity check.
     *
     * @param proximityCheckOtpLength length of OTP
     */
    public void setProximityCheckOtpLength(int proximityCheckOtpLength) {
        this.proximityCheckOtpLength = proximityCheckOtpLength;
    }

    @PostConstruct
    void validate() {
        Assert.state(proximityCheckOtpLength >= MINIMAL_PROXIMITY_CHECK_OTP_LENGTH,
                "Proximity check OTP length %d is smaller then required minimal %d".formatted(proximityCheckOtpLength, MINIMAL_PROXIMITY_CHECK_OTP_LENGTH));
    }
}
