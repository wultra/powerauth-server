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

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.crypto.ProtocolVersionValidationService;
import com.wultra.security.powerauth.app.server.service.crypto.v3.EncryptionServiceEcies;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.request.v3.VaultUnlockRequestPayload;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResultVaultUnlock;
import com.wultra.security.powerauth.app.server.service.model.response.v3.VaultUnlockResponsePayload;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.request.v3.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.VaultUnlockResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifySignatureResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Behavior class implementing the vault unlock related processes (V3).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("vaultUnlockServiceBehaviorV3")
@Slf4j
@AllArgsConstructor
public class VaultUnlockServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final EncryptionServiceEcies encryptionService;
    private final ProtocolVersionValidationService protocolVersionValidationService;

    // Helper classes
    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();
    private final ObjectMapper objectMapper;
    private final OnlineSignatureServiceBehavior onlineSignatureServiceBehavior;

    private static final Pattern VAULT_UNLOCK_REASON_PATTERN = Pattern.compile("[A-Za-z0-9_\\-.]{3,255}");

    /**
     * Method to retrieve the vault unlock key.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response with a properly encrypted vault unlock key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws GenericServiceException {
        protocolVersionValidationService.checkProtocolVersionSupported(3);
        try {
            // Get request data
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String signature = request.getSignature();
            final SignatureType signatureType = request.getSignatureType();
            final String signatureVersion = request.getSignatureVersion();
            final String signedData = request.getSignedData();

            // Build encrypted request
            final EciesEncryptedRequest encryptedRequest = new EciesEncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // The only allowed signature type is POSSESSION_KNOWLEDGE to prevent attacks with weaker signature types
            if (!signatureType.equals(SignatureType.POSSESSION_KNOWLEDGE)) {
                // POSSESSION_BIOMETRY can also be used, but must be explicitly allowed in the configuration.
                if (!(signatureType.equals(SignatureType.POSSESSION_BIOMETRY) &&
                        powerAuthServiceConfiguration.isSecureVaultBiometricAuthenticationEnabled())) {
                    logger.warn("Invalid signature type: {}", signatureType);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_AUTHENTICATION_CODE);
                }
            }

            // Lookup the activation
            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);

            // Check if the activation is in correct state
            if (activationOptional.isEmpty() || activationOptional.get().getActivationStatus() != ActivationStatus.ACTIVE) {
                // Return response with invalid signature flag when activation is not valid
                final VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            final ActivationRecordEntity activation = activationOptional.get();

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            // Get application version
            final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
            // Check if application version is valid
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Return response with invalid signature flag when application version is not valid
                final VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            // Decrypt request to obtain vault unlock reason
            final EncryptionContext context = new EncryptionContext(signatureVersion, applicationKey, activationId, EncryptorId.VAULT_UNLOCK);
            final DecryptionResultVaultUnlock decryptionResult = (DecryptionResultVaultUnlock) encryptionService.decryptRequest(encryptedRequest, context);

            // Convert JSON data to vault unlock request object
            VaultUnlockRequestPayload vaultUnlockRequest;
            try {
                vaultUnlockRequest = objectMapper.readValue(decryptionResult.getDecryptedData(), VaultUnlockRequestPayload.class);
            } catch (JacksonException ex) {
                logger.warn("Invalid vault unlock request, activation ID: {}", activationId);
                // Return response with invalid signature flag when request format is not valid
                final VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            final String reason = vaultUnlockRequest.getReason();

            if (reason != null && !VAULT_UNLOCK_REASON_PATTERN.matcher(reason).matches()) {
                logger.warn("Invalid vault unlock reason: {}", reason);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Save vault unlock reason into additional info which is logged in signature audit log.
            // If value unlock reason is missing, use default NOT_SPECIFIED value.
            final KeyValue entry = new KeyValue();
            entry.setKey(AdditionalInformation.Key.VAULT_UNLOCKED_REASON);
            entry.setValue(Objects.requireNonNullElse(reason, AdditionalInformation.Reason.VAULT_UNLOCKED_REASON_NOT_SPECIFIED));
            final List<KeyValue> additionalInformationList = new ArrayList<>();
            additionalInformationList.add(entry);

            // Verify the signature
            final VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
            verifySignatureRequest.setActivationId(activationId);
            verifySignatureRequest.setSignatureType(signatureType);
            verifySignatureRequest.setSignature(signature);
            verifySignatureRequest.setData(signedData);
            verifySignatureRequest.setApplicationKey(applicationKey);
            verifySignatureRequest.setSignatureVersion(signatureVersion);
            final VerifySignatureResponse signatureResponse = onlineSignatureServiceBehavior.verifySignature(verifySignatureRequest, additionalInformationList);

            final VaultUnlockResponsePayload responsePayload = new VaultUnlockResponsePayload();

            if (signatureResponse.isSignatureValid()) {
                // Store encrypted vault unlock key in response
                final byte[] encryptedVaultEncryptionKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(decryptionResult.getServerPrivateKey(), decryptionResult.getDevicePublicKey());
                final String encryptedVaultEncryptionKey = Base64.getEncoder().encodeToString(encryptedVaultEncryptionKeyBytes);
                responsePayload.setEncryptedVaultEncryptionKey(encryptedVaultEncryptionKey);
            }

            // Convert response payload to bytes
            final byte[] reponsePayloadBytes = objectMapper.writeValueAsBytes(responsePayload);

            // Encrypt response payload
            final EciesEncryptedResponse encryptedResponse = (EciesEncryptedResponse) decryptionResult.getServerEncryptor().encryptResponse(reponsePayloadBytes);

            // Return vault unlock response, set signature validity
            final com.wultra.security.powerauth.client.model.response.v3.VaultUnlockResponse response = new com.wultra.security.powerauth.client.model.response.v3.VaultUnlockResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setSignatureValid(signatureResponse.isSignatureValid());
            return response;
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (JacksonException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, serialization errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
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

}