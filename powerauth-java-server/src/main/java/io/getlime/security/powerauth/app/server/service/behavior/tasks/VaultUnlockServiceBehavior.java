/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.response.VaultUnlockResponse;
import com.wultra.security.powerauth.client.model.response.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyVOConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.request.VaultUnlockRequestPayload;
import io.getlime.security.powerauth.app.server.service.model.response.VaultUnlockResponsePayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.server.keyfactory.PowerAuthServerKeyFactory;
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

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
@Component("vaultUnlockServiceBehavior")
public class VaultUnlockServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;
    private final ServerPrivateKeyVOConverter serverPrivateKeyVOConverter;
    private final ServiceBehaviorCatalogue behavior;

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final PowerAuthServerKeyFactory powerAuthServerKeyFactory = new PowerAuthServerKeyFactory();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(VaultUnlockServiceBehavior.class);

    @Autowired
    public VaultUnlockServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, ServerPrivateKeyVOConverter serverPrivateKeyVOConverter, ServiceBehaviorCatalogue behavior) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.serverPrivateKeyVOConverter = serverPrivateKeyVOConverter;
        this.behavior = behavior;
    }

    /**
     * Method to retrieve the vault unlock key. Before calling this method, it is assumed that
     * client application performs signature validation - this method should not be called unauthenticated.
     * To indicate the signature validation result, 'isSignatureValid' boolean is passed as one of the
     * method parameters.
     *
     * @param activationId           Activation ID.
     * @param applicationKey         Application key.
     * @param signature              PowerAuth signature.
     * @param signatureType          PowerAuth signature type.
     * @param signatureVersion       PowerAuth signature version.
     * @param cryptogram             ECIES cryptogram.
     * @param keyConversion          Key conversion utilities.
     * @return Vault unlock response with a properly encrypted vault unlock key.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature, SignatureType signatureType, String signatureVersion,
                                           String signedData, EciesCryptogram cryptogram, KeyConvertor keyConversion)
            throws GenericServiceException {
        try {
            // Lookup the activation
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(activationId);

            // Check if the activation is in correct state
            if (activation == null || !ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
                // Return response with invalid signature flag when activation is not valid
                VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            // Get the server private key, decrypt it if required
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyVOConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);
            final byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);
            final PrivateKey serverPrivateKey = keyConversion.convertBytesToPrivateKey(serverPrivateKeyBytes);

            // Get application version
            final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);
            // Check if application version is valid
            if (applicationVersion == null || !applicationVersion.getSupported()) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Return response with invalid signature flag when application version is not valid
                final VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            // Get application secret and transport key used in sharedInfo2 parameter of ECIES
            final byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
            final byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
            final PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            final SecretKey transportKey = powerAuthServerKeyFactory.deriveTransportKey(serverPrivateKey, devicePublicKey);
            final byte[] transportKeyBytes = keyConversion.convertSharedSecretKeyToBytes(transportKey);

            // Get decryptor for the activation
            final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForActivation((ECPrivateKey) serverPrivateKey,
                    applicationSecret, transportKeyBytes, EciesSharedInfo1.VAULT_UNLOCK);

            // Decrypt request to obtain vault unlock reason
            final byte[] decryptedData = decryptor.decryptRequest(cryptogram);

            // Convert JSON data to vault unlock request object
            final VaultUnlockRequestPayload request;
            try {
                request = objectMapper.readValue(decryptedData, VaultUnlockRequestPayload.class);
            } catch (IOException ex) {
                logger.warn("Invalid vault unlock request, activation ID: {}", activationId);
                // Return response with invalid signature flag when request format is not valid
                VaultUnlockResponse response = new VaultUnlockResponse();
                response.setSignatureValid(false);
                return response;
            }

            String reason = request.getReason();

            if (reason != null && !reason.matches("[A-Za-z0-9_\\-.]{3,255}")) {
                logger.warn("Invalid vault unlock reason: {}", reason);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
            }

            // Save vault unlock reason into additional info which is logged in signature audit log.
            // If value unlock reason is missing, use default NOT_SPECIFIED value.
            final Map<String, Object> additionalInfo = new HashMap<>();
            additionalInfo.put(AdditionalInformation.VAULT_UNLOCKED_REASON, reason != null ? reason : AdditionalInformation.VAULT_UNLOCKED_REASON_NOT_SPECIFIED);

            // Verify the signature
            final VerifySignatureResponse signatureResponse = behavior.getOnlineSignatureServiceBehavior().verifySignature(activationId, signatureType,
                    signature, signatureVersion, additionalInfo, signedData, applicationKey, null, keyConversion);

            final VaultUnlockResponsePayload responsePayload = new VaultUnlockResponsePayload();

            if (signatureResponse.isSignatureValid()) {
                // Store encrypted vault unlock key in response
                final byte[] encryptedVaultEncryptionKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(serverPrivateKey, devicePublicKey);
                final String encryptedVaultEncryptionKey = BaseEncoding.base64().encode(encryptedVaultEncryptionKeyBytes);
                responsePayload.setEncryptedVaultEncryptionKey(encryptedVaultEncryptionKey);
            }

            // Convert response payload to bytes
            final byte[] responsePayloadBytes = objectMapper.writeValueAsBytes(responsePayload);

            // Encrypt response payload
            final EciesCryptogram responseCryptogram = decryptor.encryptResponse(responsePayloadBytes);
            final String responseData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
            final String responseMac = BaseEncoding.base64().encode(responseCryptogram.getMac());

            // Return vault unlock response, set signature validity
            final VaultUnlockResponse response = new VaultUnlockResponse();
            response.setEncryptedData(responseData);
            response.setMac(responseMac);
            response.setSignatureValid(signatureResponse.isSignatureValid());
            return response;
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography errors can only occur before writing to database.
            // The only possible error could occur while generating ECIES response after signature validation,
            // however this logic is well tested and should not fail.
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (EciesException ex) {
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
        }
    }

}
