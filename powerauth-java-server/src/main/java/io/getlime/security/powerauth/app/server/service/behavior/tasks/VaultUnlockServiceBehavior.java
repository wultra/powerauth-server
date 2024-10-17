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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.VaultUnlockResponse;
import com.wultra.security.powerauth.client.model.response.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.app.server.service.model.response.VaultUnlockResponsePayload;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.app.server.service.replay.ReplayVerificationService;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

/**
 * Behavior class implementing the vault unlock related processes. The class separates the
 * logic from the main service class.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class VaultUnlockServiceBehavior {

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final ReplayVerificationService replayVerificationService;
    private final ActivationContextValidator activationValidator;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ApplicationVersionRepository applicationVersionRepository;

    // Helper classes
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();
    private final ObjectMapper objectMapper;
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();
    private final OnlineSignatureServiceBehavior onlineSignatureServiceBehavior;
    private final TemporaryKeyBehavior temporaryKeyBehavior;

    /**
     * Method to retrieve the vault unlock key. Before calling this method, it is assumed that
     * client application performs signature validation - this method should not be called unauthenticated.
     * To indicate the signature validation result, 'isSignatureValid' boolean is passed as one of the
     * method parameters.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response with a properly encrypted vault unlock key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws GenericServiceException {
        try {
            if (request.getActivationId() == null || request.getApplicationKey() == null || request.getSignature() == null
                    || request.getSignatureType() == null || request.getSignatureVersion() == null || request.getSignedData() == null) {
                logger.warn("Invalid request parameters in method vaultUnlock");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Get request data
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String signature = request.getSignature();
            final SignatureType signatureType = request.getSignatureType();
            final String signatureVersion = request.getSignatureVersion();
            final String signedData = request.getSignedData();
            final String temporaryKeyId = request.getTemporaryKeyId();

            // Build encrypted request
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    request.getTemporaryKeyId(),
                    request.getEphemeralPublicKey(),
                    request.getEncryptedData(),
                    request.getMac(),
                    request.getNonce(),
                    request.getTimestamp()
            );

            // The only allowed signature type is POSESSION_KNOWLEDGE to prevent attacks with weaker signature types
            if (!signatureType.equals(SignatureType.POSSESSION_KNOWLEDGE)) {
                // POSSESSION_BIOMETRY can also be used, but must be explicitly allowed in the configuration.
                if (!(signatureType.equals(SignatureType.POSSESSION_BIOMETRY) &&
                        powerAuthServiceConfiguration.isSecureVaultBiometricAuthenticationEnabled())) {
                    logger.warn("Invalid signature type: {}", signatureType);
                    // Rollback is not required, error occurs before writing to database
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
                }
            }

            if (!encryptorFactory.getRequestResponseValidator(signatureVersion).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid encrypted request parameters in method vaultUnlock");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            // Lookup the activation
            final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);

            // Check if the activation is in correct state
            if (activationOptional.isEmpty() || activationOptional.get().getActivationStatus() != ActivationStatus.ACTIVE) {
                // Return response with invalid signature flag when activation is not valid
                VaultUnlockResponse response = new VaultUnlockResponse();
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
                VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            if (encryptedRequest.getTimestamp() != null) {
                // Check ECIES request for replay attacks and persist unique value from request
                replayVerificationService.checkAndPersistUniqueValue(
                        UniqueValueType.ECIES_ACTIVATION_SCOPE,
                        new Date(encryptedRequest.getTimestamp()),
                        encryptedRequest.getEphemeralPublicKey(),
                        encryptedRequest.getNonce(),
                        activationId,
                        signatureVersion);
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            final byte[] serverPrivateKeyBytes = Base64.getDecoder().decode(serverPrivateKeyBase64);
            final PrivateKey serverPrivateKey = keyConvertor.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final byte[] devicePublicKeyBytes = Base64.getDecoder().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConvertor.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConvertor.convertSharedSecretKeyToBytes(transportKey);

            // Get temporary or server key, depending on availability
            final PrivateKey encryptorPrivateKey = (temporaryKeyId != null) ? temporaryKeyBehavior.temporaryPrivateKey(temporaryKeyId, applicationKey, activationId) : serverPrivateKey;

            // Get server encryptor
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    EncryptorId.VAULT_UNLOCK,
                    new EncryptorParameters(signatureVersion, applicationKey, activationId, temporaryKeyId),
                    new ServerEncryptorSecrets(encryptorPrivateKey, applicationVersion.getApplicationSecret(), transportKeyBytes)
            );
            // Decrypt request to obtain vault unlock reason
            final byte[] decryptedData = serverEncryptor.decryptRequest(encryptedRequest);

            // Convert JSON data to vault unlock request object
            VaultUnlockRequestPayload vaultUnlockRequest;
            try {
                vaultUnlockRequest = objectMapper.readValue(decryptedData, VaultUnlockRequestPayload.class);
            } catch (IOException ex) {
                logger.warn("Invalid vault unlock request, activation ID: {}", activationId);
                // Return response with invalid signature flag when request format is not valid
                VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            final String reason = vaultUnlockRequest.getReason();

            if (reason != null && !reason.matches("[A-Za-z0-9_\\-.]{3,255}")) {
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
                final byte[] encryptedVaultEncryptionKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(serverPrivateKey, devicePublicKey);
                final String encryptedVaultEncryptionKey = Base64.getEncoder().encodeToString(encryptedVaultEncryptionKeyBytes);
                responsePayload.setEncryptedVaultEncryptionKey(encryptedVaultEncryptionKey);
            }

            // Convert response payload to bytes
            final byte[] reponsePayloadBytes = objectMapper.writeValueAsBytes(responsePayload);

            // Encrypt response payload
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(reponsePayloadBytes);

            // Return vault unlock response, set signature validity
            final VaultUnlockResponse response = new VaultUnlockResponse();
            response.setEncryptedData(encryptedResponse.getEncryptedData());
            response.setMac(encryptedResponse.getMac());
            response.setNonce(encryptedResponse.getNonce());
            response.setTimestamp(encryptedResponse.getTimestamp());
            response.setSignatureValid(signatureResponse.isSignatureValid());
            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (JsonProcessingException ex) {
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
