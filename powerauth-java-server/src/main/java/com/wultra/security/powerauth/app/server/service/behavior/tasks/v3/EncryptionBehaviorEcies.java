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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.ProtocolVersionValidationService;
import com.wultra.security.powerauth.app.server.service.crypto.v3.EncryptionServiceEcies;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.request.v3.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetEciesDecryptorResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ServerEciesSecrets;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

/**
 * Behavior class implementing the ECIES encryption service logic.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class EncryptionBehaviorEcies {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final EncryptionServiceEcies encryptionService;
    private final ProtocolVersionValidationService protocolVersionValidationService;

    /**
     * Obtain ECIES decryptor parameters to allow decryption of ECIES-encrypted messages on intermediate server.
     * This interface doesn't allow keys derivation, it only provides ECIES decryptor parameters used for generic
     * encryption (sharedInfo1 = /pa/generic/**).
     * <p>
     * If activationId is not present, then it creates ECIES decryptor for application scope.
     * If activationId is present, then it creates ECIES decryptor for activation scope.
     *
     * @return ECIES decryptor parameters.
     */
    @Transactional
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws GenericServiceException {
        protocolVersionValidationService.checkProtocolVersionSupported(3);
        try {
            if (request.getActivationId() == null) {
                // Application scope
                return getEciesDecryptorParametersForApplication(request);
            } else {
                // Activation scope
                return getEciesDecryptorParametersForActivation(request);
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

    /**
     * Get ECIES decryptor parameters for application scope.
     *
     * @param request Request to get ECIES decryptor parameters.
     * @return ECIES decryptor parameters for application scope.
     * @throws GenericServiceException In case ECIES decryptor parameters could not be extracted.
     */
    private GetEciesDecryptorResponse getEciesDecryptorParametersForApplication(GetEciesDecryptorRequest request) throws GenericServiceException {
        final EncryptedRequest encryptedRequest = new EciesEncryptedRequest(
                request.getTemporaryKeyId(),
                request.getEphemeralPublicKey(),
                null,
                null,
                request.getNonce(),
                request.getTimestamp()
        );
        final EncryptionContext context = new EncryptionContext(request.getProtocolVersion(), request.getApplicationKey(), null, EncryptorId.APPLICATION_SCOPE_GENERIC);
        final EncryptorSecrets encryptorSecrets = encryptionService.deriveSecrets(encryptedRequest, context);
        return generateResponse(encryptorSecrets);
    }

    /**
     * Get ECIES decryptor parameters for activation scope.
     *
     * @param request Request to get ECIES decryptor parameters.
     * @return ECIES decryptor parameters for activation scope.
     * @throws GenericServiceException In case ECIES decryptor parameters could not be extracted.
     */
    private GetEciesDecryptorResponse getEciesDecryptorParametersForActivation(GetEciesDecryptorRequest request) throws GenericServiceException {
        final String temporaryKeyId = request.getTemporaryKeyId();
        final String activationId = request.getActivationId();
        final String ephemeralPublicKey = request.getEphemeralPublicKey();
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
                new EciesEncryptedRequest(
                        temporaryKeyId,
                        ephemeralPublicKey,
                        null,
                        null,
                        nonce,
                        timestamp
                ),
                context
        );
        return generateResponse(encryptorSecrets);
    }

    private GetEciesDecryptorResponse generateResponse(EncryptorSecrets encryptorSecrets) throws GenericServiceException {
        if (encryptorSecrets instanceof ServerEciesSecrets encryptorSecretsV3) {
            // ECIES V3.0, V3.1, V3.2
            final GetEciesDecryptorResponse response = new GetEciesDecryptorResponse();
            response.setSecretKey(Base64.getEncoder().encodeToString(encryptorSecretsV3.getEnvelopeKey()));
            response.setSharedInfo2(Base64.getEncoder().encodeToString(encryptorSecretsV3.getSharedInfo2Base()));
            return response;
        }
        logger.error("Unsupported EncryptorSecrets object");
        // Rollback is not required, database is not used for writing
        throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
    }

}