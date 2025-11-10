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
 */
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.service.crypto.v4.EncryptionServiceAead;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResult;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.client.model.request.v4.ChangePasswordRequest;
import com.wultra.security.powerauth.client.model.response.v4.ChangePasswordResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;

/**
 * Password service specific to V4.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("passwordServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class PasswordServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationRepository activationRepository;
    private final ActivationContextValidator activationValidator;
    private final EncryptionServiceAead encryptionService;
    private final ObjectMapper objectMapper;

    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_ECDHE = SharedSecretFactory.getEcdhe();
    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L3 = SharedSecretFactory.getHybridMlL3();
    private static final SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> SHARED_SECRET_HYBRID_ML_L5 = SharedSecretFactory.getHybridMlL5();

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Change the password.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param request Shared secret request.
     * @return Shared secret response.
     * @throws GenericServiceException In case password change fails.
     */
    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public ChangePasswordResponse changePassword(ChangePasswordRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();

            final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);
            activationValidator.validateActiveStatus(activation.getActivationStatus(), activation.getActivationId(), localizationProvider);

            final String applicationKey = request.getApplicationKey();
            final String protocolVersion = request.getProtocolVersion();

            // Build encrypted request
            final AeadEncryptedRequest encryptedRequest = new AeadEncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEncryptedData(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // Decrypt activation data
            final EncryptionContext context = new EncryptionContext(protocolVersion, applicationKey, activationId, EncryptorId.CHANGE_PASSWORD);
            final DecryptionResult decryptionResult = encryptionService.decryptRequest(encryptedRequest, context);
            final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = decryptionResult.getServerEncryptor();
            final SharedSecretRequest sharedSecretRequest = objectMapper.readValue(decryptionResult.getDecryptedData(), SharedSecretRequest.class);
            final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());
            final DefaultSharedSecretRequest sharedSecretRequestObject = new DefaultSharedSecretRequest();
            sharedSecretRequestObject.setAlgorithm(algorithm);
            final SharedSecretResponse secretResponse = switch (algorithm) {
                case EC_P384 -> {
                    try {
                        sharedSecretRequestObject.setEncapsulationKeys(List.of(sharedSecretRequest.getEcdhe()));
                        final ResponseCryptogram responseCryptogram = SHARED_SECRET_ECDHE.generateResponseCryptogram(sharedSecretRequestObject);

                        storeKnowledgeFactorKey(activationId, responseCryptogram.getSecretKey());

                        final DefaultSharedSecretResponse derivedResponse = (DefaultSharedSecretResponse) responseCryptogram.getSharedSecretResponse();
                        final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                        sharedSecretResponse.setEcdhe(derivedResponse.getEncapsulatedKeys().get(0));
                        yield sharedSecretResponse;
                    } catch (GenericCryptoException ex) {
                        logger.error("Cryptography error occurred", ex);
                        throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    }
                }
                case EC_P384_ML_L3, EC_P384_ML_L5 -> {
                    try {
                        sharedSecretRequestObject.setEncapsulationKeys(List.of(sharedSecretRequest.getEcdhe(), sharedSecretRequest.getMlkem()));
                        final ResponseCryptogram responseCryptogram = switch (algorithm) {
                            case EC_P384_ML_L3 -> SHARED_SECRET_HYBRID_ML_L3.generateResponseCryptogram(sharedSecretRequestObject);
                            case EC_P384_ML_L5 -> SHARED_SECRET_HYBRID_ML_L5.generateResponseCryptogram(sharedSecretRequestObject);
                            default -> throw new IllegalStateException("Unexpected algorithm during shared secret response processing: " + algorithm);
                        };

                        storeKnowledgeFactorKey(activationId, responseCryptogram.getSecretKey());

                        final DefaultSharedSecretResponse derivedResponse = (DefaultSharedSecretResponse) responseCryptogram.getSharedSecretResponse();
                        final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                        sharedSecretResponse.setEcdhe(derivedResponse.getEncapsulatedKeys().get(0));
                        sharedSecretResponse.setMlkem(derivedResponse.getEncapsulatedKeys().get(1));
                        yield sharedSecretResponse;
                    } catch (GenericCryptoException ex) {
                        logger.error("Cryptography error occurred", ex);
                        throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                    }
                }
                default -> {
                    logger.warn("Unsupported algorithm: {}", sharedSecretRequest.getAlgorithm());
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
            };
            final byte[] responseBytes = objectMapper.writeValueAsBytes(secretResponse);
            final AeadEncryptedResponse encryptedResponse = (AeadEncryptedResponse) serverEncryptor.encryptResponse(responseBytes);
            final ChangePasswordResponse response = new ChangePasswordResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setTimestamp(encryptedResponse.getTimestamp());
            return response;
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

    private void storeKnowledgeFactorKey(String activationId, SecretKey secretKey) throws GenericServiceException {
        final ActivationRecordEntity activation = activationQueryService.findActivationForUpdate(activationId).orElseThrow(() -> {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
        final byte[] secretKeyConverted = KEY_CONVERTOR.convertSharedSecretKeyToBytes(secretKey);
        final String secretKeyBase64 = Base64.getEncoder().encodeToString(secretKeyConverted);
        activation.setKnowledgeFactorKeyNext(secretKeyBase64);
        activationRepository.save(activation);
    }

}
