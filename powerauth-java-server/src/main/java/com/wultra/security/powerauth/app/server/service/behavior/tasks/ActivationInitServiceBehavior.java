/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationCommitPhaseConverter;
import com.wultra.security.powerauth.app.server.converter.ActivationOtpValidationConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationTransferType;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import com.wultra.security.powerauth.app.server.database.repository.ActivationRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.AsymmetricSignatureService;
import com.wultra.security.powerauth.app.server.service.crypto.v4.KeyPairGenerationService;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.enumeration.ActivationProtocol;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.response.InitActivationResponse;
import com.wultra.security.powerauth.crypto.lib.generator.IdentifierGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.util.PasswordHash;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Behavior class implementing activation init.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ActivationInitServiceBehavior {

    private final ApplicationRepository applicationRepository;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationRepository activationRepository;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ActivationHistoryServiceBehavior activationHistoryServiceBehavior;
    private final CallbackUrlBehavior callbackUrlBehavior;
    private final KeyPairGenerationService keyPairGenerationService;
    private final AsymmetricSignatureService asymmetricSignatureService;

    private final IdentifierGenerator identifierGenerator = new IdentifierGenerator();
    private final ObjectMapper objectMapper;

    private final ActivationOtpValidationConverter activationOtpValidationConverter = new ActivationOtpValidationConverter();
    private final ActivationCommitPhaseConverter activationCommitPhaseConverter = new ActivationCommitPhaseConverter();
    /**
     * Init activation with given parameters
     *
     * @param request Init activation request.
     * @return Response with activation initialization data
     * @throws GenericServiceException If invalid values are provided.
     */
    @Transactional
    public InitActivationResponse initActivation(InitActivationRequest request) throws GenericServiceException {
        try {
            final ActivationProtocol protocol = request.getProtocol();
            final String userId = request.getUserId();
            final String applicationId = request.getApplicationId();
            final Long maxFailureCount = request.getMaxFailureCount();
            final Date activationExpireTimestamp = request.getTimestampActivationExpire();
            final String activationOtp = request.getActivationOtp();
            final List<String> flags = request.getFlags();
            com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation = request.getActivationOtpValidation();
            final com.wultra.security.powerauth.client.model.enumeration.CommitPhase commitPhase = request.getCommitPhase();

            // Generate timestamp in advance
            final Date timestamp = new Date();

            // Find application by application key
            final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);
            if (applicationEntityOptional.isEmpty()) {
                logger.warn("Application does not exist: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = applicationEntityOptional.get();

            // Get number of max attempts from request or from constants, if not provided
            Long maxAttempt = maxFailureCount;
            if (maxAttempt == null) { // use the default value
                maxAttempt = powerAuthServiceConfiguration.getAuthenticationCodeMaxFailedAttempts();
            } else if (maxFailureCount <= 0) { // only allow custom values > 0
                logger.warn("Activation cannot be created with the specified properties: maxFailureCount");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_CREATE_FAILED);
            }

            // Get activation expiration date from request or from constants, if not provided
            Date timestampExpiration = activationExpireTimestamp;
            if (timestampExpiration == null) {
                timestampExpiration = new Date(timestamp.getTime() + powerAuthServiceConfiguration.getActivationValidityBeforeActive());
            }

            if (activationOtpValidation == null) {
                activationOtpValidation = com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE;
            }

            validateOtpValidationAndCommitPhase(activationOtpValidation, commitPhase, activationOtp);

            // Generate hash from activation OTP
            final String activationOtpHash = StringUtils.hasText(activationOtp) ? PasswordHash.hash(activationOtp.getBytes(StandardCharsets.UTF_8)) : null;

            // Generate new activation data, generate a unique activation ID
            String activationId = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationIdIterations(); i++) {
                final String tmpActivationId = identifierGenerator.generateActivationId();
                final Long activationCount = activationRepository.getActivationCount(tmpActivationId);
                if (activationCount == 0) {
                    activationId = tmpActivationId;
                    break;
                } // ... else this activation ID has a collision, reset it and try to find another one
            }
            if (activationId == null) {
                logger.error("Unable to generate activation ID");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_ID);
            }

            // Generate a unique activation code
            String activationCode = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getActivationGenerateActivationCodeIterations(); i++) {
                final String tmpActivationCode = identifierGenerator.generateActivationCode();
                final Long activationCount = activationRepository.getActivationCountByActivationCode(applicationId, tmpActivationCode);
                // Check that the temporary short activation ID is unique, otherwise generate a different activation code
                if (activationCount == 0) {
                    activationCode = tmpActivationCode;
                    break;
                }
            }
            if (activationCode == null) {
                logger.error("Unable to generate activation code");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_ACTIVATION_CODE);
            }

            final MasterKeyPairEntity masterKeyPairEntity = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);

            // Store the new activation
            final ActivationRecordEntity activation = new ActivationRecordEntity();
            activation.setActivationId(activationId);
            activation.setActivationCode(activationCode);
            activation.setActivationOtpValidation(activationOtpValidationConverter.convertTo(activationOtpValidation));
            activation.setCommitPhase(activationCommitPhaseConverter.convertTo(commitPhase));
            activation.setActivationOtp(activationOtpHash);
            activation.setExternalId(null);
            activation.setActivationName(null);
            activation.setActivationStatus(ActivationStatus.CREATED);
            activation.setCounter(0L);
            activation.setCtrDataBase64(null);
            activation.setCtrDataV4Base64(null);
            activation.setDevicePublicKeyBase64(null);
            activation.setExtras(null);
            activation.setProtocol(convertProtocol(protocol));
            activation.setPlatform(null);
            activation.setDeviceInfo(null);
            activation.setFailedAttempts(0L);
            activation.setApplication(application);
            activation.setMasterKeyPair(masterKeyPairEntity);
            activation.setMaxFailedAttempts(maxAttempt);
            activation.setTimestampActivationExpire(timestampExpiration);
            activation.setTimestampCreated(timestamp);
            activation.setTimestampLastUsed(timestamp);
            activation.setTimestampLastChange(null);
            activation.setVersion(null); // Activation version is not known yet
            activation.setUserId(userId);
            activation.setParentActivation(findActivation(request.getParentActivationId()));
            activation.setTransferType(convert(request.getTransferType()));
            if (request.getAdditionalData() != null) {
                activation.setAdditionalData(objectMapper.writeValueAsString(request.getAdditionalData()));
            }
            if (flags != null) {
                activation.getFlags().addAll(flags);
            }

            // Shared secret is empty until device public keys are received
            activation.setSharedSecret(null);
            activation.setSharedSecretEncryption(EncryptionAlgorithm.NO_ENCRYPTION);

            // Server keypair is empty until key exchange with client
            activation.setServerPrivateKeyBase64(null);
            activation.setServerPrivateKeyEncryption(EncryptionAlgorithm.NO_ENCRYPTION);

            activationHistoryServiceBehavior.saveActivationAndLogChange(activation);
            callbackUrlBehavior.notifyCallbackListenersOnActivationChange(activation);

            final Map<String, String> signatures = asymmetricSignatureService.computeSignaturesForActivation(activation);
            // Return the server response
            final InitActivationResponse response = new InitActivationResponse();
            response.setActivationId(activationId);
            response.setActivationCode(activationCode);
            response.setUserId(userId);
            response.setActivationSignature(signatures.get(JWSAlgorithm.ES256.getName()));
            response.getActivationSignatures().putAll(signatures);
            response.setApplicationId(activation.getApplication().getId());

            return response;
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
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

    private static ActivationTransferType convert(final com.wultra.security.powerauth.client.model.enumeration.ActivationTransferType source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case MOVE -> ActivationTransferType.MOVE;
            case SPAWN -> ActivationTransferType.SPAWN;
        };
    }

    private ActivationRecordEntity findActivation(final String activationId) throws GenericServiceException {
        if (activationId == null) {
            return null;
        }

        return activationRepository.findById(activationId).orElseThrow(() -> {
            logger.warn("Activation ID: {} not found", activationId);
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
    }

    private void validateOtpValidationAndCommitPhase(com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation activationOtpValidation, com.wultra.security.powerauth.client.model.enumeration.CommitPhase commitPhase, String activationOtp) throws GenericServiceException {
        // Validate combination of activation OTP and OTP validation mode.
        if (activationOtpValidation != com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE && commitPhase != null) {
            logger.warn("Invalid combination of input parameters activationOtpValidation and commitPhase.");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (activationOtpValidation != com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE && !StringUtils.hasText(activationOtp)) {
            logger.warn("Missing activation OTP for OTP validation: {}", activationOtpValidation);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    private com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol convertProtocol(final ActivationProtocol source) {
        if (source == null) {
            return null;
        }
        return switch (source) {
            case POWERAUTH -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol.POWERAUTH;
            case FIDO2 -> com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationProtocol.FIDO2;
        };
    }
}
