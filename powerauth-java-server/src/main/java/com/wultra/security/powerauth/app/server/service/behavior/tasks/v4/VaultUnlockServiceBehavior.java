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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.database.model.AdditionalInformation;
import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior;
import com.wultra.security.powerauth.app.server.service.crypto.v4.EncryptionServiceAead;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.request.EncryptionContext;
import com.wultra.security.powerauth.app.server.service.model.request.v4.VaultUnlockRequestPayload;
import com.wultra.security.powerauth.app.server.service.model.response.DecryptionResultVaultUnlock;
import com.wultra.security.powerauth.app.server.service.model.response.v4.VaultUnlockResponsePayload;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.v4.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.v4.VaultUnlockResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.*;

import static com.wultra.security.powerauth.app.server.service.behavior.tasks.ApplicationConfigServiceBehavior.CONFIG_DISABLE_BIOMETRY_UNLOCK_KEK_DEVICE_PRIVATE;

/**
 * Behavior class implementing the vault unlock related processes (V4).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("vaultUnlockServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class VaultUnlockServiceBehavior {

    private static final String KEY_ID_KEK_DEVICE_PRIVATE = "KEK_DEVICE_PRIVATE";
    private static final String KEY_ID_KDK_APP_VAULT_KNOWLEDGE = "KDK_APP_VAULT_KNOWLEDGE";
    private static final String KEY_ID_KDK_APP_VAULT_2FA = "KDK_APP_VAULT_2FA";

    private final LocalizationProvider localizationProvider;
    private final ActivationQueryService activationQueryService;
    private final ActivationContextValidator activationValidator;
    private final ApplicationVersionRepository applicationVersionRepository;
    private final EncryptionServiceAead encryptionService;
    private final ObjectMapper objectMapper;
    private final OnlineAuthenticationServiceBehavior onlineAuthenticationServiceBehavior;
    private final ActivationSharedSecretConverter activationSharedSecretConverter;
    private final ApplicationConfigServiceBehavior applicationConfigServiceBehavior;

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Method to retrieve the vault unlock key.
     *
     * @param request Vault unlock request.
     * @return Vault unlock response with requested vault unlock key.
     * @throws GenericServiceException Thrown in case of business logic error.
     */
    @Transactional
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws GenericServiceException {
        try {
            final ActivationRecordEntity activation = fetchActivation(request.getActivationId());
            validateApplicationVersion(request.getApplicationKey());
            final DecryptionResultVaultUnlock decryptionResult = decryptRequest(request);
            final VaultUnlockRequestPayload payload = parseRequestPayload(decryptionResult.getDecryptedData(), activation.getActivationId());
            checkVaultUnlockReason(payload.getReason());
            checkKeyIdentifier(payload.getKeyIdentifier(), request.getAuthenticationCodeType(), activation.getApplication().getId());
            final List<KeyValue> auditInfo = buildAuditInfo(payload.getReason());
            final VerifyAuthenticationResponse authenticationResponse = verifyAuthentication(request, auditInfo);
            final VaultUnlockResponsePayload responsePayload = new VaultUnlockResponsePayload();
            if (authenticationResponse.isAuthenticationValid()) {
                final String vaultEncryptionKey = deriveVaultEncryptionKey(payload.getKeyIdentifier(), activation);
                responsePayload.setVaultEncryptionKey(vaultEncryptionKey);
            }
            return buildVaultUnlockResponse(responsePayload, decryptionResult.getServerEncryptor(), authenticationResponse.isAuthenticationValid());
        } catch (EncryptorException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.DECRYPTION_FAILED);
        } catch (JsonProcessingException ex) {
            logger.error(ex.getMessage(), ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        } catch (GenericServiceException ex) {
            // already logged or thrown with context
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
     * Fetch and validate activation by ID.
     *
     * @param activationId Activation ID.
     * @return Activation entity.
     * @throws GenericServiceException Thrown in case activation is missing or in invalid state.
     */
    private ActivationRecordEntity fetchActivation(String activationId) throws GenericServiceException {
        final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationWithoutLock(activationId);
        if (activationOptional.isEmpty() || activationOptional.get().getActivationStatus() != ActivationStatus.ACTIVE) {
            logger.warn("Activation not found or not active, activationId: {}", activationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final ActivationRecordEntity activation = activationOptional.get();
        activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);
        return activation;
    }

    /**
     * Validate an application version by application key.
     *
     * @param applicationKey Application key.
     * @throws GenericServiceException Thrown in case application is missing or not supported.
     */
    private void validateApplicationVersion(String applicationKey) throws GenericServiceException {
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            logger.warn("Application version is incorrect, application key: {}", applicationKey);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Decrypt the incoming AEAD request.
     *
     * @param request Vault unlock request.
     * @return Vault unlok decryption result.
     * @throws GenericServiceException Thrown in case of any cryptography error.
     */
    private DecryptionResultVaultUnlock decryptRequest(VaultUnlockRequest request) throws GenericServiceException {
        final EncryptionContext context = new EncryptionContext(
                request.getAuthenticationVersion(),
                request.getApplicationKey(),
                request.getActivationId(),
                EncryptorId.VAULT_UNLOCK
        );
        final AeadEncryptedRequest encryptedRequest = new AeadEncryptedRequest(
                request.getTemporaryKeyId(),
                request.getEncryptedData(),
                request.getNonce(),
                request.getTimestamp()
        );
        return (DecryptionResultVaultUnlock) encryptionService.decryptRequest(encryptedRequest, context);
    }

    /**
     * Parse and validate the decrypted JSON payload.
     *
     * @param data         Decrypted data.
     * @param activationId Activation identifier.
     * @return Parsed VaultUnlockRequestPayload.
     * @throws GenericServiceException Thrown in case of deserialization errors.
     */
    private VaultUnlockRequestPayload parseRequestPayload(byte[] data, String activationId) throws GenericServiceException {
        try {
            return objectMapper.readValue(data, VaultUnlockRequestPayload.class);
        } catch (IOException ex) {
            logger.warn("Invalid vault unlock request, activation ID: {}", activationId, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Build the audit information for vault unlock.
     *
     * @param reason Vault unlock reason.
     * @return List with a single KeyValue for the audit log.
     */
    private List<KeyValue> buildAuditInfo(String reason) {
        final KeyValue entry = new KeyValue();
        entry.setKey(AdditionalInformation.Key.VAULT_UNLOCKED_REASON);
        entry.setValue(Objects.requireNonNullElse(reason, AdditionalInformation.Reason.VAULT_UNLOCKED_REASON_NOT_SPECIFIED));
        return Collections.singletonList(entry);
    }

    /**
     * Verifies the client authentication code using the online authentication service.
     *
     * @param request                Vault unlock request.
     * @param additionalInformation  Audit info.
     * @return Authentication response.
     */
    private VerifyAuthenticationResponse verifyAuthentication(VaultUnlockRequest request, List<KeyValue> additionalInformation) throws GenericServiceException {
        final VerifyAuthenticationRequest verifyRequest = new VerifyAuthenticationRequest();
        verifyRequest.setActivationId(request.getActivationId());
        verifyRequest.setAuthenticationCodeType(request.getAuthenticationCodeType());
        verifyRequest.setAuthenticationCode(request.getAuthenticationCode());
        verifyRequest.setData(request.getRequestData());
        verifyRequest.setApplicationKey(request.getApplicationKey());
        verifyRequest.setAuthenticationVersion(request.getAuthenticationVersion());
        return onlineAuthenticationServiceBehavior.verifyAuthentication(verifyRequest, additionalInformation);
    }

    /**
     * Derive the vault encryption key from the activation and return it in Base64 format.
     *
     * @param keyIdentifier   Key identifier.
     * @param activation      Activation entity.
     * @return Base64-encoded vault encryption key.
     * @throws GenericServiceException Thrown in case the activation secret cannot be extracted.
     * @throws GenericCryptoException  Thrown in case key derivation fails.
     */
    private String deriveVaultEncryptionKey(String keyIdentifier, ActivationRecordEntity activation) throws GenericServiceException, GenericCryptoException {
        final SecretKey activationSecretKey = extractActivationSecretKey(activation);
        final SecretKey vaultEncryptionKey = deriveVaultEncryptionKey(keyIdentifier, activationSecretKey);
        final byte[] keyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(vaultEncryptionKey);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * Build the encrypted response payload for the vault unlock operation.
     *
     * @param responsePayload     Response data payload.
     * @param encryptor           Server encryptor.
     * @param authenticationValid Whether authentication was valid.
     * @return Vault unlock response.
     * @throws JsonProcessingException Thrown in case serialization fails.
     * @throws EncryptorException      Thrown in case encryption fails.
     */
    private VaultUnlockResponse buildVaultUnlockResponse(VaultUnlockResponsePayload responsePayload, ServerEncryptor<EncryptedRequest, EncryptedResponse> encryptor, boolean authenticationValid) throws JsonProcessingException, EncryptorException {
        final byte[] responsePayloadBytes = objectMapper.writeValueAsBytes(responsePayload);
        final AeadEncryptedResponse encryptedResponse = (AeadEncryptedResponse) encryptor.encryptResponse(responsePayloadBytes);
        final VaultUnlockResponse response = new VaultUnlockResponse();
        response.setEncryptedData(encryptedResponse.getEncryptedData());
        response.setTimestamp(encryptedResponse.getTimestamp());
        response.setAuthenticationValid(authenticationValid);
        return response;
    }

    /**
     * Derive the requested vault encryption key.
     *
     * @param keyIdentifier         Key identifier.
     * @param keyActivationSecret   Activation shared secret key.
     * @return Derived SecretKey.
     * @throws GenericCryptoException Thrown in case key could not be derived.
     */
    private SecretKey deriveVaultEncryptionKey(String keyIdentifier, SecretKey keyActivationSecret) throws GenericCryptoException {
        return switch (keyIdentifier) {
            case KEY_ID_KEK_DEVICE_PRIVATE -> KeyFactory.deriveKeyKekDevicePrivate(keyActivationSecret);
            case KEY_ID_KDK_APP_VAULT_KNOWLEDGE -> KeyFactory.deriveKeyKdkAppVaultKnowledge(keyActivationSecret);
            case KEY_ID_KDK_APP_VAULT_2FA -> KeyFactory.deriveKeyKdkAppVault2fa(keyActivationSecret);
            // Impossible state due to validation
            default -> throw new IllegalArgumentException("Unsupported key identifier: " + keyIdentifier);
        };
    }

    /**
     * Check the key identifier.
     *
     * @param keyIdentifier          Key identifier.
     * @param authenticationCodeType Authentication code type.
     * @param applicationId          Application identifier.
     * @throws GenericServiceException Thrown in case key identifier is invalid.
     */
    private void checkKeyIdentifier(String keyIdentifier, AuthenticationCodeType authenticationCodeType, String applicationId) throws GenericServiceException {
        if (keyIdentifier == null) {
            logger.warn("Missing key identifier");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (!keyIdentifier.equals(KEY_ID_KEK_DEVICE_PRIVATE)
                && !keyIdentifier.equals(KEY_ID_KDK_APP_VAULT_KNOWLEDGE)
                && !keyIdentifier.equals(KEY_ID_KDK_APP_VAULT_2FA)) {
            logger.warn("Invalid key identifier: {}", keyIdentifier);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (keyIdentifier.equals(KEY_ID_KEK_DEVICE_PRIVATE) && !isUnlockAllowedKekDevicePrivate(authenticationCodeType, applicationId)) {
            logger.warn("Invalid authentication code type {} for key identifier {}", authenticationCodeType, keyIdentifier);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (keyIdentifier.equals(KEY_ID_KDK_APP_VAULT_KNOWLEDGE) && !authenticationCodeType.equals(AuthenticationCodeType.POSSESSION_KNOWLEDGE)) {
            logger.warn("Invalid authentication code type {} for key identifier {}", authenticationCodeType, keyIdentifier);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (keyIdentifier.equals(KEY_ID_KDK_APP_VAULT_2FA)
                && !(authenticationCodeType.equals(AuthenticationCodeType.POSSESSION_KNOWLEDGE) || authenticationCodeType.equals(AuthenticationCodeType.POSSESSION_BIOMETRY))) {
            logger.warn("Invalid authentication code type {} for key identifier {}", authenticationCodeType, keyIdentifier);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Determine whether vault unlock is allowed for KEK_DEVICE_PRIVATE based on application configuration.
     * @param authenticationCodeType Authentication code type.
     * @param applicationId          Application identifier.
     * @return Whether vault unlock is allowed for KEK_DEVICE_PRIVATE.
     */
    private boolean isUnlockAllowedKekDevicePrivate(AuthenticationCodeType authenticationCodeType, String applicationId) {
        if (authenticationCodeType.equals(AuthenticationCodeType.POSSESSION_KNOWLEDGE)) {
            return true;
        }
        if (authenticationCodeType.equals(AuthenticationCodeType.POSSESSION_BIOMETRY)) {
            final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
            configRequest.setApplicationId(applicationId);
            final GetApplicationConfigResponse configResponse = applicationConfigServiceBehavior.getApplicationConfig(configRequest);
            for (ApplicationConfigurationItem config: configResponse.getApplicationConfigs()) {
                if (config.getKey().equals(CONFIG_DISABLE_BIOMETRY_UNLOCK_KEK_DEVICE_PRIVATE)) {
                    // Configuration is set for disable_biometry_unlock_kek_device_private, use the setting
                    return config.getValues().size() == 1 && !config.getValues().get(0).equals("true");
                }
            }
            // Configuration is not set for disable_biometry_unlock_kek_device_private = true, biometry can be used
            return true;
        }
        return false;
    }

    /**
     * Check the format of the vault unlock reason.
     *
     * @param reason Vault unlock reason.
     * @throws GenericServiceException Thrown in case vault unlock reason format is invalid.
     */
    private void checkVaultUnlockReason(String reason) throws GenericServiceException {
        if (reason != null && !reason.matches("[A-Za-z0-9_\\-.]{3,255}")) {
            logger.warn("Invalid vault unlock reason: {}", reason);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        }
    }

    /**
     * Extract the activation secret key from activation entity.
     *
     * @param activation Activation entity.
     * @return Activation shared secret key.
     * @throws GenericServiceException Thrown in case key conversion fails.
     */
    private SecretKey extractActivationSecretKey(ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecret activationSharedSecret = new SharedSecret(activation.getSharedSecretEncryption(), activation.getSharedSecret());
        final String activationSecretBase64 = activationSharedSecretConverter.fromDBValue(activationSharedSecret, activation.getUserId(), activation.getActivationId());
        final byte[] activationSecretBytes = Base64.getDecoder().decode(activationSecretBase64);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(activationSecretBytes);
    }

}
