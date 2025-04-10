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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.v4.EncryptionServiceAead;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.request.v4.ExtractEncryptorRequest;
import com.wultra.security.powerauth.client.model.response.v4.ExtractEncryptorResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

/**
 * Behavior class implementing the AEAD encryption service logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class EncryptionBehaviorAead {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final EncryptionServiceAead encryptionService;

    /**
     * Extract AEAD encryptor parameters to allow decryption of AEAD-encrypted messages on intermediate server.
     * <p>
     * If activationId is not present, then it creates AEAD encryptor for application scope.
     * If activationId is present, then it creates AEAD encryptor for activation scope.
     * @param request Extract encryptor parameters request.
     * @return Extract encryptor parameters response.
     * @throws GenericServiceException In case encryptor parameters could not be extracted.
     */
    @Transactional
    public ExtractEncryptorResponse extractEncryptor(ExtractEncryptorRequest request) throws GenericServiceException {
        try {
            if (request.getActivationId() == null) {
                // Application scope
                return extractEncryptorParametersForApplication(request);
            } else {
                // Activation scope
                return extractEncryptorParametersForActivation(request);
            }
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    private ExtractEncryptorResponse extractEncryptorParametersForApplication(ExtractEncryptorRequest request) throws GenericServiceException {
        final EncryptedRequest encryptedRequest = new AeadEncryptedRequest(
                request.getTemporaryKeyId(),
                null,
                request.getNonce(),
                request.getTimestamp()
        );
        final EncryptionContext context = new EncryptionContext(request.getProtocolVersion(), request.getApplicationKey(), null, EncryptorId.APPLICATION_SCOPE_GENERIC);

        final EncryptorSecrets encryptorSecrets = encryptionService.deriveSecrets(encryptedRequest, context);
        if (encryptorSecrets instanceof AeadSecrets aeadSecrets) {
            // AEAD in V4
            final ExtractEncryptorResponse response = new ExtractEncryptorResponse();
            response.setSecretKey(Base64.getEncoder().encodeToString(aeadSecrets.getEnvelopeKey()));
            response.setSharedInfo2(Base64.getEncoder().encodeToString(aeadSecrets.getSharedInfo2()));
            return response;
        }
        logger.error("Unsupported EncryptorSecrets object");
        // Rollback is not required, database is not used for writing
        throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
    }

    private ExtractEncryptorResponse extractEncryptorParametersForActivation(ExtractEncryptorRequest request) throws GenericServiceException {
        final String temporaryKeyId = request.getTemporaryKeyId();
        final String activationId = request.getActivationId();
        final Long timestamp = request.getTimestamp();
        final String nonce = request.getNonce();

        // Lookup the activation
        final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.info("Activation does not exist, activation ID: {}", activationId);
            // Rollback is not required, database is not used for writing
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });

        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

        activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

        final EncryptionContext context = new EncryptionContext(request.getProtocolVersion(), request.getApplicationKey(), activationId, EncryptorId.ACTIVATION_SCOPE_GENERIC);
        final EncryptorSecrets encryptorSecrets = encryptionService.deriveSecrets(
                new AeadEncryptedRequest(
                        temporaryKeyId,
                        null,
                        nonce,
                        timestamp
                ),
                context
        );
        if (encryptorSecrets instanceof AeadSecrets aeadSecrets) {
            // AEAD V4.0
            final ExtractEncryptorResponse response = new ExtractEncryptorResponse();
            response.setSecretKey(Base64.getEncoder().encodeToString(aeadSecrets.getEnvelopeKey()));
            response.setSharedInfo2(Base64.getEncoder().encodeToString(aeadSecrets.getSharedInfo2()));
            return response;
        }
        logger.error("Unsupported EncryptorSecrets object");
        // Rollback is not required, database is not used for writing
        throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
    }

}