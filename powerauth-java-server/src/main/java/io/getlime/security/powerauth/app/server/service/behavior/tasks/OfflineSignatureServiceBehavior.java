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

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusVOConverter;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyVOConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.signature.OfflineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class OfflineSignatureServiceBehavior {

    private static final String APPLICATION_SECRET_OFFLINE_MODE = "offline";
    private static final String KEY_MASTER_SERVER_PRIVATE_INDICATOR = "0";
    private static final String KEY_SERVER_PRIVATE_INDICATOR = "1";

    private final RepositoryCatalogue repositoryCatalogue;
    private final SignatureSharedServiceBehavior signatureSharedServiceBehavior;
    private final LocalizationProvider localizationProvider;

    // Prepare converters
    private final ActivationStatusVOConverter activationStatusVOConverter = new ActivationStatusVOConverter();
    private ServerPrivateKeyVOConverter serverPrivateKeyVOConverter;

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(OfflineSignatureServiceBehavior.class);

    @Autowired
    public OfflineSignatureServiceBehavior(RepositoryCatalogue repositoryCatalogue, SignatureSharedServiceBehavior signatureSharedServiceBehavior, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.signatureSharedServiceBehavior = signatureSharedServiceBehavior;
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setServerPrivateKeyConverter(ServerPrivateKeyVOConverter serverPrivateKeyVOConverter) {
        this.serverPrivateKeyVOConverter = serverPrivateKeyVOConverter;
    }

    /**
     * Verify signature for given activation and provided data in offline mode. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureTypes         Signature types to try to use during verification of offline signature.
     * @param signature              Provided signature.
     * @param dataString             String with data used to compute the signature.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, List<SignatureType> signatureTypes, String signature, Map<String, Object> additionalInfo, String dataString, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        try {
            return verifyOfflineSignatureImpl(activationId, signatureTypes, signature, additionalInfo, dataString, keyConversionUtilities);
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create personalized offline signature payload for displaying a QR code in offline mode.
     * @param activationId Activation ID.
     * @param data Normalized data used for offline signature verification.
     * @param keyConversionUtilities Key convertor.
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data, KeyConvertor keyConversionUtilities) throws GenericServiceException {

        // Fetch activation details from the repository
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        final ActivationRecordEntity activation = activationRepository.findActivationWithoutLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }

        // Proceed and compute the results
        try {

            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            final String nonce = BaseEncoding.base64().encode(nonceBytes);

            // Decrypt server private key (depending on encryption mode)
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyVOConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);

            // Decode the private key - KEY_SERVER_PRIVATE is used for personalized offline signatures
            final PrivateKey privateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(serverPrivateKeyBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = BaseEncoding.base64().encode(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (data + "\n" + nonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

            // Return the result
            final CreatePersonalizedOfflineSignaturePayloadResponse response = new CreatePersonalizedOfflineSignaturePayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;

        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Create non-personalized offline signature payload for displaying a QR code in offline mode.
     * @param applicationId Application ID.
     * @param data Normalized data used for offline signature verification.
     * @param keyConversionUtilities Key convertor.
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data, KeyConvertor keyConversionUtilities) throws GenericServiceException {
        // Fetch associated master key pair data from the repository
        final MasterKeyPairRepository masterKeyPairRepository = repositoryCatalogue.getMasterKeyPairRepository();
        final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
        if (masterKeyPair == null) {
            logger.error("No master key pair found for application ID: {}", applicationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
        }

        // Proceed and compute the results
        try {

            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            final String nonce = BaseEncoding.base64().encode(nonceBytes);

            // Prepare the private key - KEY_MASTER_SERVER_PRIVATE is used for non-personalized offline signatures
            final String keyPrivateBase64 = masterKeyPair.getMasterKeyPrivateBase64();
            final PrivateKey privateKey = keyConversionUtilities.convertBytesToPrivateKey(BaseEncoding.base64().decode(keyPrivateBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = BaseEncoding.base64().encode(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

            // Return the result
            final CreateNonPersonalizedOfflineSignaturePayloadResponse response = new CreateNonPersonalizedOfflineSignaturePayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;

        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE);
        } catch (CryptoProviderException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_CRYPTO_PROVIDER);
        }
    }

    /**
     * Verify offline signature implementation.
     * @param activationId Activation ID.
     * @param signatureTypes Signature types to try to use for signature verification.
     * @param signature Signature.
     * @param additionalInfo Additional information related to signature verification.
     * @param dataString Signature data.
     * @param keyConversionUtilities Key convertor.
     * @return Verify offline signature response.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private VerifyOfflineSignatureResponse verifyOfflineSignatureImpl(String activationId, List<SignatureType> signatureTypes, String signature, Map<String, Object> additionalInfo, String dataString, KeyConvertor keyConversionUtilities)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        // Fetch related activation
        final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);

        // Only validate signature for existing ACTIVE activation records
        if (activation != null) {

            // Application secret is "offline" in offline mode
            final byte[] data = (dataString + "&" + APPLICATION_SECRET_OFFLINE_MODE).getBytes(StandardCharsets.UTF_8);
            final SignatureData signatureData = new SignatureData(data, signature, PowerAuthSignatureFormat.DECIMAL, null, additionalInfo, null);
            final OfflineSignatureRequest offlineSignatureRequest = new OfflineSignatureRequest(signatureData, signatureTypes);

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                final SignatureResponse verificationResponse = signatureSharedServiceBehavior.verifySignature(activation, offlineSignatureRequest, keyConversionUtilities);

                // Check if the signature is valid
                if (verificationResponse.isSignatureValid()) {

                    signatureSharedServiceBehavior.handleValidSignature(activation, verificationResponse, offlineSignatureRequest, currentTimestamp);

                    return validSignatureResponse(activation, verificationResponse.getUsedSignatureType());

                } else {

                    signatureSharedServiceBehavior.handleInvalidSignature(activation, verificationResponse, offlineSignatureRequest, currentTimestamp);

                    return invalidSignatureResponse(activation, offlineSignatureRequest);

                }
            } else {

                signatureSharedServiceBehavior.handleInactiveActivationSignature(activation, offlineSignatureRequest, currentTimestamp);

                // return the data
                return invalidStateResponse(activationId, activation.getActivationStatus());

            }
        } else { // Activation does not exist

            return invalidStateResponse(activationId, ActivationStatus.REMOVED);

        }
    }

    /**
     * Generates an invalid signature response when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     * @param activationId Activation ID.
     * @param activationStatus Activation status.
     * @return Invalid signature response.
     */
    private VerifyOfflineSignatureResponse invalidStateResponse(String activationId, ActivationStatus activationStatus) {
        final VerifyOfflineSignatureResponse response = new VerifyOfflineSignatureResponse();
        response.setActivationId(activationId);
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusVOConverter.convert(activationStatus));
        return response;
    }

    /**
     * Generates a valid signature response when signature validation succeeded.
     * @param activation Activation ID.
     * @param usedSignatureType Signature type which was used during validation of the signature.
     * @return Valid signature response.
     */
    private VerifyOfflineSignatureResponse validSignatureResponse(ActivationRecordEntity activation, SignatureType usedSignatureType) {
        // Extract application ID and application roles
        final Long applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineSignatureResponse response = new VerifyOfflineSignatureResponse();
        response.setSignatureValid(true);
        response.setActivationStatus(activationStatusVOConverter.convert(ActivationStatus.ACTIVE));
        response.setBlockedReason(null);
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        response.setSignatureType(usedSignatureType);
        return response;
    }

    /**
     * Generates an invalid signature response when signature validation failed.
     * @param activation Activation ID.
     * @param offlineSignatureRequest Signature request.
     * @return Invalid signature response.
     */
    private VerifyOfflineSignatureResponse invalidSignatureResponse(ActivationRecordEntity activation, OfflineSignatureRequest offlineSignatureRequest) {
        // Calculate remaining attempts
        final long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        // Extract application ID and application roles
        final Long applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineSignatureResponse response = new com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusVOConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        // In case multiple signature types are used, use the first one as signature type
        response.setSignatureType(offlineSignatureRequest.getSignatureTypes().iterator().next());
        return response;
    }
}
