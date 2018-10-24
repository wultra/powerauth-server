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

package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.database.model.KeyEncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.util.KeyDerivationUtil;
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
import io.getlime.security.powerauth.crypto.server.vault.PowerAuthServerVault;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.v3.KeyValueMap;
import io.getlime.security.powerauth.v3.SignatureType;
import io.getlime.security.powerauth.v3.VaultUnlockResponse;
import io.getlime.security.powerauth.v3.VerifySignatureResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the vault unlock related processes. The class separates the
 * logic from the main service class.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("VaultUnlockServiceBehavior")
public class VaultUnlockServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;
    private final ActivationRepository powerAuthRepository;
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;
    private final ServiceBehaviorCatalogue behavior;

    // Helper classes
    private final EciesFactory eciesFactory = new EciesFactory();
    private final KeyDerivationUtil keyDerivationUtil = new KeyDerivationUtil();
    private final PowerAuthServerVault powerAuthServerVault = new PowerAuthServerVault();
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Prepare converters
    private ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    @Autowired
    public VaultUnlockServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, ActivationRepository powerAuthRepository, ServerPrivateKeyConverter serverPrivateKeyConverter, ServiceBehaviorCatalogue behavior) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.powerAuthRepository = powerAuthRepository;
        this.serverPrivateKeyConverter = serverPrivateKeyConverter;
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
     * @param cryptogram             ECIES cryptogram.
     * @param keyConversion          Key conversion utilities.
     * @return Vault unlock response with a properly encrypted vault unlock key.
     * @throws InvalidKeySpecException In case invalid key is provided.
     * @throws InvalidKeyException     In case invalid key is provided.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature, SignatureType signatureType,
                                           String signedData, EciesCryptogram cryptogram, CryptoProviderUtil keyConversion)
            throws GenericServiceException, InvalidKeySpecException, InvalidKeyException, EciesException, UnsupportedEncodingException, JsonProcessingException {

        // Lookup the activation
        final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);

        // Check if the activation is in correct state
        if (activation == null || !ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
            // Return response with invalid signature flag when activation is not valid
            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setSignatureValid(false);
            return response;
        }

        // Get the server private key, decrypt it if required
        final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
        final KeyEncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
        final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity, activation.getUserId(), activation.getActivationId());
        byte[] serverPrivateKeyBytes = BaseEncoding.base64().decode(serverPrivateKeyBase64);
        final PrivateKey serverPrivateKey = keyConversion.convertBytesToPrivateKey(serverPrivateKeyBytes);

        // Get application version
        final ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);
        // Check if application version is valid
        if (applicationVersion == null || !applicationVersion.getSupported()) {
            // Return response with invalid signature flag when application version is not valid
            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setSignatureValid(false);
            return response;
        }

        // Get application secret and transport key used in sharedInfo2 parameter of ECIES
        byte[] applicationSecret = applicationVersion.getApplicationSecret().getBytes(StandardCharsets.UTF_8);
        byte[] devicePublicKeyBytes = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
        byte[] transportKeyBytes = keyDerivationUtil.deriveTransportKey(serverPrivateKeyBytes, devicePublicKeyBytes);

        // Get decryptor for the activation
        final EciesDecryptor decryptor = eciesFactory.getEciesDecryptorForActivation((ECPrivateKey) serverPrivateKey,
                applicationSecret, transportKeyBytes, EciesSharedInfo1.VAULT_UNLOCK);

        // Decrypt request to obtain vault unlock reason
        byte[] decryptedData = decryptor.decryptRequest(cryptogram);

        // Convert JSON data to vault unlock request object
        VaultUnlockRequestPayload request;
        try {
            request = objectMapper.readValue(decryptedData, VaultUnlockRequestPayload.class);
        } catch (IOException ex) {
            // Return response with invalid signature flag when request format is not valid
            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setSignatureValid(false);
            return response;
        }

        String reason = request.getReason();

        if (reason != null && reason.length() > 255) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        }

        // Save vault unlock reason into additional info which is logged in signature audit log.
        // If value unlock reason is missing, use default NOT_SPECIFIED value.
        KeyValueMap additionalInfo = new KeyValueMap();
        KeyValueMap.Entry entry = new KeyValueMap.Entry();
        entry.setKey(AdditionalInformation.VAULT_UNLOCKED_REASON);
        if (reason == null) {
            entry.setValue(AdditionalInformation.VAULT_UNLOCKED_REASON_NOT_SPECIFIED);
        } else {
            entry.setValue(reason);
        }
        additionalInfo.getEntry().add(entry);

        // Verify the signature
        VerifySignatureResponse signatureResponse = behavior.getSignatureServiceBehavior().verifySignature(activationId, signatureType,
                signature, additionalInfo, signedData, applicationKey, null, keyConversion);

        VaultUnlockResponsePayload responsePayload = new VaultUnlockResponsePayload();

        if (signatureResponse.isSignatureValid()) {
            // Store encrypted vault unlock key in response
            PublicKey devicePublicKey = keyConversion.convertBytesToPublicKey(devicePublicKeyBytes);
            byte[] encryptedVaultEncryptionKeyBytes = powerAuthServerVault.encryptVaultEncryptionKey(serverPrivateKey, devicePublicKey);
            String encryptedVaultEncryptionKey = BaseEncoding.base64().encode(encryptedVaultEncryptionKeyBytes);
            responsePayload.setEncryptedVaultEncryptionKey(encryptedVaultEncryptionKey);
        }

        // Convert response payload to bytes
        byte[] reponsePayloadBytes = objectMapper.writeValueAsBytes(responsePayload);

        // Encrypt response payload
        EciesCryptogram responseCryptogram = decryptor.encryptResponse(reponsePayloadBytes);
        String responseData = BaseEncoding.base64().encode(responseCryptogram.getEncryptedData());
        String responseMac = BaseEncoding.base64().encode(responseCryptogram.getMac());

        // Return vault unlock response, set signature validity
        VaultUnlockResponse response = new VaultUnlockResponse();
        response.setEncryptedData(responseData);
        response.setMac(responseMac);
        response.setSignatureValid(signatureResponse.isSignatureValid());
        return response;
    }

}
