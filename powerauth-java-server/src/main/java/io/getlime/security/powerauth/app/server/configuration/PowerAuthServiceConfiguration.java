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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;

/**
 * Class holding the configuration data of this PowerAuth 2.0 Server
 * instance. Default values are in "application.properties" file.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Configuration
public class PowerAuthServiceConfiguration {

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
    private int activationGenerateActivationIdIterations;

    /**
     * When a duplicate token ID is encountered during the token generation, how
     * many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateTokenIdIterations}")
    private int generateTokenIdIterations;

    /**
     * When a duplicate activation short ID is encountered during the
     * activation, how many times generate a new one.
     */
    @Value("${powerauth.service.crypto.generateActivationShortIdIterations}")
    private int activationGenerateActivationShortIdIterations;

    /**
     * How many milliseconds should be CREATED or OTP_USED record usable for
     * completing the activation.
     */
    @Value("${powerauth.service.crypto.activationValidityInMilliseconds}")
    private int activationValidityBeforeActive;

    /**
     * How many failed signatures cause activation record blocking.
     */
    @Value("${powerauth.service.crypto.signatureMaxFailedAttempts}")
    private long signatureMaxFailedAttempts;

    /**
     * When validating the signature, how many iterations ahead too look in case
     * signature fails for the first counter value.
     */
    @Value("${powerauth.service.crypto.signatureValidationLookahead}")
    private long signatureValidationLookahead;

    /**
     * Master DB encryption key.
     */
    @Value("${powerauth.server.db.master.encryption.key}")
    private String masterDbEncryptionKey;

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
     * Get number of short activation ID generation attempts in case of collision.
     * @return Retry iteration count (10, by default).
     */
    public int getActivationGenerateActivationShortIdIterations() {
        return activationGenerateActivationShortIdIterations;
    }

    /**
     * Set number of short activation ID generation attempts in case of collision.
     * @param activationGenerateActivationShortIdIterations Retry iteration count (10, by default).
     */
    public void setActivationGenerateActivationShortIdIterations(int activationGenerateActivationShortIdIterations) {
        this.activationGenerateActivationShortIdIterations = activationGenerateActivationShortIdIterations;
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
     * Get length of the period of activation record validity during activation.
     * @return How long the activation is valid before it expires (2 minutes, in milliseconds, by default).
     */
    public int getActivationValidityBeforeActive() {
        return activationValidityBeforeActive;
    }

    /**
     * Get length of the period of activation record validity during activation.
     * @param activationValidityBeforeActive How long the activation is valid before it expires (2 minutes, in milliseconds by defaults).
     */
    public void setActivationValidityBeforeActive(int activationValidityBeforeActive) {
        this.activationValidityBeforeActive = activationValidityBeforeActive;
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

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("/i18n/errors_");
        source.setUseCodeAsDefaultMessage(true);
        return source;
    }

}
