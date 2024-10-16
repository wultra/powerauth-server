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

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.CreateNonPersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.ServerPrivateKeyConverter;
import io.getlime.security.powerauth.app.server.database.model.ServerPrivateKey;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.signature.OfflineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.crypto.lib.config.DecimalSignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.totp.Totp;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @link <a href="https://github.com/wultra/powerauth-webflow/blob/develop/docs/Off-line-Signatures-QR-Code.md">Off-line Signature QR Code</a>
 */
@Service
@AllArgsConstructor
@Slf4j
public class OfflineSignatureServiceBehavior {

    private static final String APPLICATION_SECRET_OFFLINE_MODE = "offline";
    private static final String KEY_MASTER_SERVER_PRIVATE_INDICATOR = "0";
    private static final String KEY_SERVER_PRIVATE_INDICATOR = "1";

    private final SignatureSharedServiceBehavior signatureSharedServiceBehavior;
    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationContextValidator activationValidator;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ApplicationRepository applicationRepository;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final ServerPrivateKeyConverter serverPrivateKeyConverter;

    /**
     * Verify signature for given activation and provided data in offline mode. Log every validation attempt in the audit log.
     *
     * @param request parameter object
     * @return Response with the signature validation result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VerifyOfflineSignatureResponse verifyOfflineSignature(final VerifyOfflineSignatureRequest request)
            throws GenericServiceException {
        try {
            if (request.getActivationId() == null || request.getData() == null || request.getSignature() == null) {
                logger.warn("Invalid request parameters in method verifyOfflineSignature");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final String activationId = request.getActivationId();
            final BigInteger componentLength = request.getComponentLength();
            final List<SignatureType> allowedSignatureTypes = new ArrayList<>();
            // The order of signature types is important. PowerAuth server logs first found signature type
            // as used signature type in case signature verification fails. In case the POSSESSION_BIOMETRY signature
            // type is allowed, additional info in signature audit contains flag BIOMETRY_ALLOWED.
            allowedSignatureTypes.add(SignatureType.POSSESSION_KNOWLEDGE);
            if (request.isAllowBiometry()) {
                allowedSignatureTypes.add(SignatureType.POSSESSION_BIOMETRY);
            }
            final int expectedComponentLength = (componentLength != null) ? componentLength.intValue() : powerAuthServiceConfiguration.getOfflineSignatureComponentLength();

            final VerifyOfflineSignatureParameter signatureParameter = convert(request, expectedComponentLength, allowedSignatureTypes, keyConvertor);
            return verifyOfflineSignatureImpl(signatureParameter);
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
     * Create personalized offline signature payload for displaying a QR code in offline mode.
     * @param request parameter object
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(final CreatePersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        try {
            if (request.getActivationId() == null || request.getData() == null) {
                logger.warn("Invalid request parameters in method createPersonalizedOfflineSignaturePayload");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Fetch activation details from the repository
            final String activationId = request.getActivationId();
            final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            final OfflineSignatureParameter offlineSignatureParameter = convert(request);

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final String nonce = fetchNonce(offlineSignatureParameter);

            // Decrypt server private key (depending on encryption mode)
            final String serverPrivateKeyFromEntity = activation.getServerPrivateKeyBase64();
            final EncryptionMode serverPrivateKeyEncryptionMode = activation.getServerPrivateKeyEncryption();
            final ServerPrivateKey serverPrivateKeyEncrypted = new ServerPrivateKey(serverPrivateKeyEncryptionMode, serverPrivateKeyFromEntity);
            final String serverPrivateKeyBase64 = serverPrivateKeyConverter.fromDBValue(serverPrivateKeyEncrypted, activation.getUserId(), activationId);

            // Decode the private key - KEY_SERVER_PRIVATE is used for personalized offline signatures
            final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(serverPrivateKeyBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}'
            // {DATA} consist of data from request plus optional generated proximity TOTP value
            final SignatureUtils signatureUtils = new SignatureUtils();
            final String dataPlusNonce = fetchDataAndTotp(offlineSignatureParameter, powerAuthServiceConfiguration.getProximityCheckOtpLength()) + "\n" + nonce;
            final byte[] signatureBase = (dataPlusNonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = Base64.getEncoder().encodeToString(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (dataPlusNonce + "\n" + KEY_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

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

    private static String fetchDataAndTotp(OfflineSignatureParameter request, int digitsNumber) throws CryptoProviderException {
        if (StringUtils.isBlank(request.getProximityCheckSeed())) {
            return request.getData();
        }
        logger.debug("Generating TOTP for proximity check, activation ID: {}", request.getActivationId());
        final byte[] seed = Base64.getDecoder().decode(request.getProximityCheckSeed());
        final byte[] totp = Totp.generateTotpSha256(seed, Instant.now(), request.getProximityCheckStepLength(), digitsNumber);
        return request.getData() + "\n" + new String(totp, StandardCharsets.UTF_8);
    }

    private static String fetchNonce(OfflineSignatureParameter request) throws CryptoProviderException {
        if (StringUtils.isNotBlank(request.getNonce())) {
            logger.debug("Using provided nonce, activation ID: {}", request.getActivationId());
            return request.getNonce();
        }

        logger.debug("Generating random nonce, activation ID: {}", request.getActivationId());
        final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    /**
     * Create non-personalized offline signature payload for displaying a QR code in offline mode.
     * @param request Request with offline signature payload.
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String data = request.getData();

            if (data == null) {
                logger.warn("Invalid request parameter data in method createNonPersonalizedOfflineSignaturePayload");
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            // Fetch associated master key pair data from the repository
            final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);
            if (applicationEntityOptional.isEmpty()) {
                logger.warn("No application found with ID: {}", applicationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
            if (masterKeyPair == null) {
                logger.error("No master key pair found for application ID: {}", applicationId);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }
            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            final String nonce = Base64.getEncoder().encodeToString(nonceBytes);

            // Prepare the private key - KEY_MASTER_SERVER_PRIVATE is used for non-personalized offline signatures
            final String keyPrivateBase64 = masterKeyPair.getMasterKeyPrivateBase64();
            final PrivateKey privateKey = keyConvertor.convertBytesToPrivateKey(Base64.getDecoder().decode(keyPrivateBase64));

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}'
            final SignatureUtils signatureUtils = new SignatureUtils();
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = signatureUtils.computeECDSASignature(signatureBase, privateKey);
            final String ecdsaSignature = Base64.getEncoder().encodeToString(ecdsaSignatureBytes);

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
     * Verify offline signature implementation.
     * @param request parameter object
     * @return Verify offline signature response.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private VerifyOfflineSignatureResponse verifyOfflineSignatureImpl(final VerifyOfflineSignatureParameter request)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        final String activationId = request.getActivationId();

        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationForUpdate(activationId);
        if (activationOptional.isEmpty()) {
            return invalidStateResponse(activationId, ActivationStatus.REMOVED);
        }

        final ActivationRecordEntity activation = activationOptional.get();

        // If case of proximity check enabled, there are more signatures to validate
        final List<OfflineSignatureRequest> offlineSignatureRequests = createOfflineSignatureRequests(request);

        if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

            // Double-check that there are at least some remaining attempts
            if (activation.getFailedAttempts() >= activation.getMaxFailedAttempts()) { // ... otherwise, the activation should be already blocked
                signatureSharedServiceBehavior.handleInactiveActivationWithMismatchSignature(activation, offlineSignatureRequests.get(0), currentTimestamp);
                return invalidStateResponse(activationId, activation.getActivationStatus());
            }

            SignatureResponse verificationResponse = new SignatureResponse();
            OfflineSignatureRequest offlineSignatureRequest = new OfflineSignatureRequest();
            for (OfflineSignatureRequest item : offlineSignatureRequests) {
                verificationResponse = signatureSharedServiceBehavior.verifySignature(activation, item, request.getKeyConversionUtilities());
                offlineSignatureRequest = item;
                if (verificationResponse.isSignatureValid()) {
                    break;
                }
            }

            // Check if the signature is valid
            if (verificationResponse.isSignatureValid()) {

                signatureSharedServiceBehavior.handleValidSignature(activation, verificationResponse, offlineSignatureRequest, currentTimestamp);

                return validSignatureResponse(activation, verificationResponse.getUsedSignatureType());

            } else {

                signatureSharedServiceBehavior.handleInvalidSignature(activation, verificationResponse, offlineSignatureRequest, currentTimestamp);

                return invalidSignatureResponse(activation, offlineSignatureRequest);

            }
        } else {

            signatureSharedServiceBehavior.handleInactiveActivationSignature(activation, offlineSignatureRequests.get(0), currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());

        }
    }

    /**
     * Prepare {@link OfflineSignatureRequest} from the given request.
     * If proximity check enabled, append OTP to {@link  OfflineSignatureRequest#getSignatureData()}.
     *
     * @param request verify offline signature parameter
     * @return offline signature request
     * @throws CryptoProviderException in case of a problem to generate the TOTP
     */
    private List<OfflineSignatureRequest> createOfflineSignatureRequests(final VerifyOfflineSignatureParameter request) throws CryptoProviderException {
        final List<String> proximityOtps = fetchProximityCheckOtps(request);
        if (proximityOtps.isEmpty()) {
            return List.of(createOfflineSignatureRequest(request));
        }

        final List<OfflineSignatureRequest> result = new ArrayList<>();
        for (String otp : proximityOtps) {
            result.add(createOfflineSignatureRequestWithPostFix(request, otp));
        }
        return result;
    }

    private OfflineSignatureRequest createOfflineSignatureRequest(final VerifyOfflineSignatureParameter request) {
        return createOfflineSignatureRequest(request, request.getDataString());
    }

    private OfflineSignatureRequest createOfflineSignatureRequestWithPostFix(final VerifyOfflineSignatureParameter request, final String otp) {
        final String[] signatureBaseElements = request.getDataString().split("&");
        final int dataElementIndex = signatureBaseElements.length - 1;
        // Original data ${operationId}&${operationData}
        final String originalDataBase64 = signatureBaseElements[dataElementIndex];
        final String originalData = new String(Base64.getDecoder().decode(originalDataBase64), StandardCharsets.UTF_8);
        // Data with appended otp ${operationId}&${operationData}&${otp}
        final String dataWithPostFix = originalData + "&" + otp;
        final String dataWithPostFixBase64 = Base64.getEncoder().encodeToString(dataWithPostFix.getBytes(StandardCharsets.UTF_8));
        signatureBaseElements[dataElementIndex] = dataWithPostFixBase64;
        final String signatureBaseString = String.join("&", signatureBaseElements);
        return createOfflineSignatureRequest(request, signatureBaseString);
    }

    private OfflineSignatureRequest createOfflineSignatureRequest(final VerifyOfflineSignatureParameter request, final String signatureBase) {
        // Application secret is "offline" in offline mode
        final byte[] data = (signatureBase + "&" + APPLICATION_SECRET_OFFLINE_MODE).getBytes(StandardCharsets.UTF_8);
        final DecimalSignatureConfiguration signatureConfiguration = SignatureConfiguration.decimal();
        if (request.getExpectedComponentLength() != null) {
            signatureConfiguration.setLength(request.getExpectedComponentLength());
        }
        final SignatureData signatureData = new SignatureData(data, request.getSignature(), signatureConfiguration, null, request.getAdditionalInfo(), null);
        return new OfflineSignatureRequest(signatureData, request.getSignatureTypes());
    }

    /**
     * If proximity check is enabled, generates a list of TOTP to validate. Otherwise, an empty collection is returned.
     *
     * @param request request verify offline signature parameter
     * @return list of TOTPs or empty collection
     * @throws CryptoProviderException CryptoProviderException in case of a problem to generate the TOTP
     */
    private List<String> fetchProximityCheckOtps(final VerifyOfflineSignatureParameter request) throws CryptoProviderException {
        if (StringUtils.isBlank(request.getProximityCheckSeed())) {
            logger.debug("Proximity seed is not present and is TOTP not being verified, activation ID: {}", request.getActivationId());
            return Collections.emptyList();
        }

        final int digitsNumber = powerAuthServiceConfiguration.getProximityCheckOtpLength();
        final int steps = request.getProximityCheckStepCount();
        logger.debug("Generating TOTP, activation ID: {}, steps count: {}", request.getActivationId(), steps);

        final byte[] seed = Base64.getDecoder().decode(request.getProximityCheckSeed());
        final List<String> result = new ArrayList<>();

        final Duration stepLength = request.getProximityCheckStepLength();
        final Instant now = Instant.now();
        for (int i = 0; i <= steps; i++) {
            final Instant instant = now.minus(stepLength.multipliedBy(i));
            logger.debug("Generating TOTP, activation ID: {}, instant: {}", request.getActivationId(), instant);
            final byte[] totp = Totp.generateTotpSha256(seed, instant, stepLength, digitsNumber);
            result.add(new String(totp, StandardCharsets.UTF_8));
        }

        return result;
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
        response.setActivationStatus(activationStatusConverter.convert(activationStatus));
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
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineSignatureResponse response = new VerifyOfflineSignatureResponse();
        response.setSignatureValid(true);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
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
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineSignatureResponse response = new VerifyOfflineSignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
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

    private static OfflineSignatureParameter convert(final CreatePersonalizedOfflineSignaturePayloadRequest request) {
        final var builder = OfflineSignatureParameter.builder()
                .activationId(request.getActivationId())
                .data(request.getData())
                .nonce(request.getNonce());

        if (request.getProximityCheck() != null) {
            logger.debug("Proximity check enabled, activation ID: {}", request.getActivationId());
            builder.proximityCheckSeed(request.getProximityCheck().getSeed());
            builder.proximityCheckStepLength(Duration.ofSeconds(request.getProximityCheck().getStepLength()));
        }

        return builder.build();
    }

    private static VerifyOfflineSignatureParameter convert(
            final VerifyOfflineSignatureRequest request,
            final int expectedComponentLength,
            final List<SignatureType> allowedSignatureTypes,
            final KeyConvertor keyConvertor) {

        final var builder = VerifyOfflineSignatureParameter.builder()
                .activationId(request.getActivationId())
                .signatureTypes(allowedSignatureTypes)
                .signature(request.getSignature())
                .additionalInfo(new ArrayList<>())
                .dataString(request.getData())
                .expectedComponentLength(expectedComponentLength)
                .keyConversionUtilities(keyConvertor);

        final var proximityCheck = request.getProximityCheck();
        if (proximityCheck != null) {
            logger.debug("Proximity check enabled, activation ID: {}", request.getActivationId());
            builder.proximityCheckSeed(proximityCheck.getSeed());
            builder.proximityCheckStepLength(Duration.ofSeconds(proximityCheck.getStepLength()));
            builder.proximityCheckStepCount(proximityCheck.getStepCount());
        }

        return builder.build();
    }


}
