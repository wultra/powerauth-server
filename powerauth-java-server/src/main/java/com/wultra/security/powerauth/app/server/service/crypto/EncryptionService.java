/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for handling encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
@AllArgsConstructor
public abstract class EncryptionService {

    private final LocalizationProvider localizationProvider;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final ActivationQueryService activationQueryService;

    /**
     * Decrypt an encrypted request.
     * @param encryptedRequest Encrypted request.
     * @param protocolVersion Cryptography protocol version.
     * @param applicationKey Application key.
     * @param activationId Activation ID.
     * @param encryptorId Encryptor ID.
     * @param validateRequest Whether request should be validated.
     * @return Decryption result.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public abstract DecryptionResult decrypt(EncryptedRequest encryptedRequest, String protocolVersion, String applicationKey, String activationId, EncryptorId encryptorId, boolean validateRequest) throws GenericServiceException;

    /**
     * Decrypt an encrypted request using server encryptor.
     *
     * @param encryptedRequest Encrypted request.
     * @param context Encryption context.
     * @return Decrypted data and context.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public DecryptionResult decryptRequest(EncryptedRequest encryptedRequest, EncryptionContext context) throws GenericServiceException {
        try {
            final DecryptionResult decryptionResult = decrypt(
                    encryptedRequest,
                    context.getProtocolVersion(),
                    context.getApplicationKey(),
                    context.getActivationId(),
                    context.getEncryptorId(),
                    true
            );
            final byte[] decrypted = decryptionResult.getServerEncryptor().decryptRequest(encryptedRequest);
            decryptionResult.setDecryptedData(decrypted);
            return decryptionResult;
        } catch (EncryptorException e) {
            logger.error("Decryption failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
    }

    /**
     * Derive encryptor secrets.
     *
     * @param encryptedRequest Encrypted request without encrypted data.
     * @param context Encryption context.
     * @return Encryptor secrets.
     * @throws GenericServiceException In case of a cryptography error.
     */
    public EncryptorSecrets deriveSecrets(EncryptedRequest encryptedRequest, EncryptionContext context) throws GenericServiceException {
        try {
            final DecryptionResult decryptionResult = decrypt(
                    encryptedRequest,
                    context.getProtocolVersion(),
                    context.getApplicationKey(),
                    context.getActivationId(),
                    context.getEncryptorId(),
                    false
            );
            return decryptionResult.getServerEncryptor().deriveSecretsForExternalEncryptor(encryptedRequest);
        } catch (EncryptorException e) {
            logger.error("Decryption failed", e);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        }
    }

    /**
     * Helper method for finding application version by application key during decryption.
     * @param applicationKey Application key.
     * @return Application version entity.
     * @throws GenericServiceException In case application version does not exist, or it is not supported.
     */
    protected ApplicationVersionEntity findApplicationVersion(String applicationKey) throws GenericServiceException {
        // Find application by application key
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
        if (applicationVersion == null || !applicationVersion.getSupported() || applicationVersion.getApplication() == null) {
            logger.warn("Application version is incorrect, application key: {}", applicationKey);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_EXPIRED);
        }
        return applicationVersion;
    }

    /**
     * Helper method for finding activation during decryption.
     * @param activationId Activation ID.
     * @return Activation entity.
     * @throws GenericServiceException In case activation does not exist.
     */
    protected ActivationRecordEntity findActivation(String activationId) throws GenericServiceException {
        if (activationId == null) {
            return null;
        }
        return activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, database is not used for writing
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
    }
}
