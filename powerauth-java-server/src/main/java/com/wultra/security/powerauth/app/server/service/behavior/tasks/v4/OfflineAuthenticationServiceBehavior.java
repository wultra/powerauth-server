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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.database.repository.MasterKeyPairRepository;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyServiceFactory;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.authentication.v4.*;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.util.SharedSecretExtractor;
import com.wultra.security.powerauth.app.server.service.validator.ActivationContextValidator;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.CreateNonPersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreatePersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyOfflineAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.v4.CreateNonPersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreatePersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyOfflineAuthenticationResponse;
import com.wultra.security.powerauth.crypto.lib.config.DecimalAuthenticationCodeConfiguration;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.totp.Totp;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Behavior class implementing the offline authentication code validation related processes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class OfflineAuthenticationServiceBehavior {

    private static final String APPLICATION_SECRET_OFFLINE_MODE = "offline";
    private static final String KEY_MASTER_SERVER_PRIVATE_INDICATOR = "0";
    private static final byte[] KMAC_JOSE_SIGNATURE_CUSTOM_BYTES = "JOSE".getBytes(StandardCharsets.UTF_8);

    private final AuthenticationSharedServiceBehavior authenticationSharedServiceBehavior;
    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;
    private final ActivationContextValidator activationValidator;
    private final MasterKeyPairRepository masterKeyPairRepository;
    private final ApplicationRepository applicationRepository;
    private final SharedSecretExtractor sharedSecretExtractor;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final CryptographyServiceFactory cryptographyServiceFactory;

    /**
     * Verify authentication for given activation and provided data in offline mode. Log every validation attempt in the audit log.
     *
     * @param request parameter object
     * @return Response with the authentication validation result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(final VerifyOfflineAuthenticationRequest request)
            throws GenericServiceException {
        try {
            final BigInteger componentLength = request.getComponentLength();
            final List<AuthenticationCodeType> allowedAuthenticationTypes = new ArrayList<>();
            // The order of authentication code types is important. PowerAuth server logs first found authentication code type
            // as used authentication code type in case authentication code verification fails. In case the POSSESSION_BIOMETRY authentication code
            // type is allowed, additional info in authentication audit contains flag BIOMETRY_ALLOWED.
            allowedAuthenticationTypes.add(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
            if (request.isAllowBiometry()) {
                allowedAuthenticationTypes.add(AuthenticationCodeType.POSSESSION_BIOMETRY);
            }
            final int expectedComponentLength = (componentLength != null) ? componentLength.intValue() : powerAuthServiceConfiguration.getOfflineAuthenticationCodeComponentLength();

            final VerifyOfflineAuthenticationParameter authenticationParameter = convert(request, expectedComponentLength, allowedAuthenticationTypes);
            return verifyOfflineAuthenticationImpl(authenticationParameter);
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        } catch (GenericCryptoException ex) {
            logger.error(ex.getMessage(), ex);
            // Rollback is not required, cryptography methods are executed before database is used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_COMPUTE_AUTHENTICATION_CODE);
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
     * Create personalized offline authentication payload for displaying a QR code in offline mode.
     * @param request parameter object
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(final CreatePersonalizedOfflineAuthPayloadRequest request) throws GenericServiceException {
        try {
            // Fetch activation details from the repository
            final String activationId = request.getActivationId();
            final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, database is not used for writing
                return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            });

            final OfflineAuthenticationParameter offlineAuthenticationParameter = convert(request);

            activationValidator.validatePowerAuthProtocol(activation.getProtocol(), localizationProvider);

            final String nonce = fetchNonce(offlineAuthenticationParameter);

            // Compute KMAC-256 of '{DATA}\n{NONCE}
            // {DATA} consist of data from request plus optional generated proximity TOTP value
            final String dataPlusNonce = fetchDataAndTotp(offlineAuthenticationParameter, powerAuthServiceConfiguration.getProximityCheckOtpLength()) + "\n" + nonce;
            final byte[] kmacData = (dataPlusNonce).getBytes(StandardCharsets.UTF_8);

            final SecretKey activationSecretKey = sharedSecretExtractor.extractActivationSecretKey(activation);
            final SecretKey keyMacPersonalisedData = KeyFactory.deriveKeyMacPersonalizedData(activationSecretKey);

            // Construct KMAC-256 tag
            final byte[] tagKmac = Kmac.kmac256(keyMacPersonalisedData, kmacData, KMAC_JOSE_SIGNATURE_CUSTOM_BYTES, 64);
            final String signature = createJwsJson(Base64URL.encode(tagKmac));

            // Construct complete offline data as '{DATA}\n{NONCE}\n{SIGNATURE}'
            final String offlineData = (dataPlusNonce + "\n" + signature);

            // Return the result
            final CreatePersonalizedOfflineAuthPayloadResponse response = new CreatePersonalizedOfflineAuthPayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;
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
     * Create a JSON with JWS signatures from a KMAC-256 tag.
     * @param kmacTag KMAC-256 tag.
     * @return JSON with JWS signatures array.
     */
    private String createJwsJson(Base64URL kmacTag) {
        final JWSHeader header = new JWSHeader.Builder(new JWSAlgorithm("KMAC256")).build();
        final Base64URL protectedHeader = header.toBase64URL();
        final Map<String, Object> signatureMap = new LinkedHashMap<>();
        signatureMap.put("protected", protectedHeader.toString());
        signatureMap.put("signature", kmacTag.toString());
        return "[" + JSONObjectUtils.toJSONString(signatureMap) + "]";
    }

    private static String fetchDataAndTotp(OfflineAuthenticationParameter request, int digitsNumber) throws CryptoProviderException {
        if (StringUtils.isBlank(request.getProximityCheckSeed())) {
            return request.getData();
        }
        logger.debug("Generating TOTP for proximity check, activation ID: {}", request.getActivationId());
        final byte[] seed = Base64.getDecoder().decode(request.getProximityCheckSeed());
        final byte[] totp = Totp.generateTotpSha256(seed, Instant.now(), request.getProximityCheckStepLength(), digitsNumber);
        return request.getData() + "\n" + new String(totp, StandardCharsets.UTF_8);
    }

    private static String fetchNonce(OfflineAuthenticationParameter request) throws CryptoProviderException {
        if (StringUtils.isNotBlank(request.getNonce())) {
            logger.debug("Using provided nonce, activation ID: {}", request.getActivationId());
            return request.getNonce();
        }

        logger.debug("Generating random nonce, activation ID: {}", request.getActivationId());
        final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    /**
     * Create non-personalized offline authentication payload for displaying a QR code in offline mode.
     * @param request Request with offline authentication payload.
     * @return Response with data for QR code and cryptographic nonce.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(CreateNonPersonalizedOfflineAuthPayloadRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String data = request.getData();

            // Fetch associated master key pair data from the repository
            final Optional<ApplicationEntity> applicationEntityOptional = applicationRepository.findById(applicationId);
            if (applicationEntityOptional.isEmpty()) {
                logger.warn("No application found with ID: {}", applicationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = applicationEntityOptional.get();
            final MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
            if (masterKeyPair == null) {
                logger.error("No master key pair found for application ID: {}", applicationId);
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.NO_MASTER_SERVER_KEYPAIR);
            }
            // Generate nonce
            final byte[] nonceBytes = new KeyGenerator().generateRandomBytes(16);
            final String nonce = Base64.getEncoder().encodeToString(nonceBytes);

            // Compute ECDSA signature of '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}'
            final byte[] signatureBase = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR).getBytes(StandardCharsets.UTF_8);
            final byte[] ecdsaSignatureBytes = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384).generateSignatureForApplication(KeyType.ECDSA_P384, signatureBase, application);
            final String ecdsaSignature = Base64.getEncoder().encodeToString(ecdsaSignatureBytes);

            // Construct complete offline data as '{DATA}\n{NONCE}\n{KEY_MASTER_SERVER_PRIVATE_INDICATOR}{ECDSA_SIGNATURE}'
            final String offlineData = (data + "\n" + nonce + "\n" + KEY_MASTER_SERVER_PRIVATE_INDICATOR + ecdsaSignature);

            // Return the result
            final CreateNonPersonalizedOfflineAuthPayloadResponse response = new CreateNonPersonalizedOfflineAuthPayloadResponse();
            response.setOfflineData(offlineData);
            response.setNonce(nonce);
            return response;
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
     * Verify offline authentication implementation.
     *
     * @param request parameter object
     * @return Verify offline authentication response.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws InvalidKeyException     In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws GenericCryptoException  In case of a cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private VerifyOfflineAuthenticationResponse verifyOfflineAuthenticationImpl(final VerifyOfflineAuthenticationParameter request)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        final String activationId = request.getActivationId();

        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationForUpdate(activationId);
        if (activationOptional.isEmpty()) {
            return invalidStateResponse(activationId, ActivationStatus.REMOVED);
        }

        final ActivationRecordEntity activation = activationOptional.get();

        // If case of proximity check enabled, there are more authentication requests to validate
        final List<OfflineAuthenticationRequest> offlineAuthenticationRequests = createOfflineAuthenticationRequests(request);

        if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

            // Double-check that there are at least some remaining attempts
            if (activation.getFailedAttempts() >= activation.getMaxFailedAttempts()) { // ... otherwise, the activation should be already blocked
                authenticationSharedServiceBehavior.handleInactiveActivationWithMismatchAuthentication(activation, offlineAuthenticationRequests.get(0), currentTimestamp);
                return invalidStateResponse(activationId, activation.getActivationStatus());
            }

            AuthenticationResponse verificationResponse = new AuthenticationResponse();
            OfflineAuthenticationRequest offlineAuthenticationRequest = new OfflineAuthenticationRequest();
            for (OfflineAuthenticationRequest item : offlineAuthenticationRequests) {
                verificationResponse = authenticationSharedServiceBehavior.verifyAuthentication(activation, item);
                offlineAuthenticationRequest = item;
                if (verificationResponse.isAuthenticationValid()) {
                    break;
                }
            }

            // Check if the authentication is valid
            if (verificationResponse.isAuthenticationValid()) {

                authenticationSharedServiceBehavior.handleValidAuthentication(activation, verificationResponse, offlineAuthenticationRequest, currentTimestamp);

                return validAuthenticationResponse(activation, verificationResponse.getUsedAuthenticationCodeType());

            } else {

                authenticationSharedServiceBehavior.handleInvalidAuthentication(activation, verificationResponse, offlineAuthenticationRequest, currentTimestamp);

                return invalidAuthenticationResponse(activation, offlineAuthenticationRequest);

            }
        } else {

            authenticationSharedServiceBehavior.handleInactiveActivationAuthentication(activation, offlineAuthenticationRequests.get(0), currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());

        }
    }

    /**
     * Prepare {@link OfflineAuthenticationRequest} from the given request.
     * If proximity check enabled, append OTP to {@link OfflineAuthenticationRequest#getAuthenticationData()} ()}.
     *
     * @param request verify offline authentication parameter
     * @return offline authentication request
     * @throws CryptoProviderException in case of a problem to generate the TOTP
     */
    private List<OfflineAuthenticationRequest> createOfflineAuthenticationRequests(final VerifyOfflineAuthenticationParameter request) throws CryptoProviderException {
        final List<String> proximityOtps = fetchProximityCheckOtps(request);
        if (proximityOtps.isEmpty()) {
            return List.of(createOfflineAuthenticationRequest(request));
        }

        final List<OfflineAuthenticationRequest> result = new ArrayList<>();
        for (String otp : proximityOtps) {
            result.add(createOfflineAuthenticationRequestWithPostFix(request, otp));
        }
        return result;
    }

    private OfflineAuthenticationRequest createOfflineAuthenticationRequest(final VerifyOfflineAuthenticationParameter request) {
        return createOfflineAuthenticationRequest(request, request.getDataString());
    }

    private OfflineAuthenticationRequest createOfflineAuthenticationRequestWithPostFix(final VerifyOfflineAuthenticationParameter request, final String otp) {
        final String[] baseElements = request.getDataString().split("&");
        final int dataElementIndex = baseElements.length - 1;
        // Original data ${operationId}&${operationData}
        final String originalDataBase64 = baseElements[dataElementIndex];
        final String originalData = new String(Base64.getDecoder().decode(originalDataBase64), StandardCharsets.UTF_8);
        // Data with appended otp ${operationId}&${operationData}&${otp}
        final String dataWithPostFix = originalData + "&" + otp;
        final String dataWithPostFixBase64 = Base64.getEncoder().encodeToString(dataWithPostFix.getBytes(StandardCharsets.UTF_8));
        baseElements[dataElementIndex] = dataWithPostFixBase64;
        final String baseString = String.join("&", baseElements);
        return createOfflineAuthenticationRequest(request, baseString);
    }

    private OfflineAuthenticationRequest createOfflineAuthenticationRequest(final VerifyOfflineAuthenticationParameter request, final String authenticationBase) {
        // Application secret is "offline" in offline mode
        final byte[] data = (authenticationBase + "&" + APPLICATION_SECRET_OFFLINE_MODE).getBytes(StandardCharsets.UTF_8);
        final DecimalAuthenticationCodeConfiguration powerAuthConfiguration = DecimalAuthenticationCodeConfiguration.decimal();
        if (request.getExpectedComponentLength() != null) {
            powerAuthConfiguration.setLength(request.getExpectedComponentLength());
        }
        final AuthenticationData authenticationData = new AuthenticationData(data, request.getAuthenticationCode(), powerAuthConfiguration, null, request.getAdditionalInfo());
        return new OfflineAuthenticationRequest(authenticationData, request.getAuthenticationCodeTypes());
    }

    /**
     * If proximity check is enabled, generates a list of TOTP to validate. Otherwise, an empty collection is returned.
     *
     * @param request request verify offline authentication parameter
     * @return list of TOTPs or empty collection
     * @throws CryptoProviderException CryptoProviderException in case of a problem to generate the TOTP
     */
    private List<String> fetchProximityCheckOtps(final VerifyOfflineAuthenticationParameter request) throws CryptoProviderException {
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
     * Generates an invalid authentication response when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     * @param activationId Activation ID.
     * @param activationStatus Activation status.
     * @return Invalid authentication response.
     */
    private VerifyOfflineAuthenticationResponse invalidStateResponse(String activationId, ActivationStatus activationStatus) {
        final VerifyOfflineAuthenticationResponse response = new VerifyOfflineAuthenticationResponse();
        response.setActivationId(activationId);
        response.setAuthenticationValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activationStatus));
        return response;
    }

    /**
     * Generates a valid authentication response when authentication validation succeeded.
     * @param activation Activation ID.
     * @param usedAuthenticationType Authentication code type which was used during validation of the authentication code.
     * @return Valid authentication response.
     */
    private VerifyOfflineAuthenticationResponse validAuthenticationResponse(ActivationRecordEntity activation, AuthenticationCodeType usedAuthenticationType) {

        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineAuthenticationResponse response = new VerifyOfflineAuthenticationResponse();
        response.setAuthenticationValid(true);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
        response.setBlockedReason(null);
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        response.setAuthenticationCodeType(usedAuthenticationType);
        return response;
    }

    /**
     * Generates an invalid authentication response when authentication validation failed.
     * @param activation Activation ID.
     * @param offlineAuthenticationRequest Offline authentication request.
     * @return Invalid authentication response.
     */
    private VerifyOfflineAuthenticationResponse invalidAuthenticationResponse(ActivationRecordEntity activation, OfflineAuthenticationRequest offlineAuthenticationRequest) {
        // Calculate remaining attempts
        final long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifyOfflineAuthenticationResponse response = new VerifyOfflineAuthenticationResponse();
        response.setAuthenticationValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        response.getActivationFlags().addAll(activationFlags);
        // In case multiple authentication code types are used, use the first one as authentication code type
        response.setAuthenticationCodeType(offlineAuthenticationRequest.getAuthenticationCodeTypes().iterator().next());
        return response;
    }

    private static OfflineAuthenticationParameter convert(final CreatePersonalizedOfflineAuthPayloadRequest request) {
        final var builder = OfflineAuthenticationParameter.builder()
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

    private static VerifyOfflineAuthenticationParameter convert(
            final VerifyOfflineAuthenticationRequest request,
            final int expectedComponentLength,
            final List<AuthenticationCodeType> allowedAuthenticationTypes) {

        final var builder = VerifyOfflineAuthenticationParameter.builder()
                .activationId(request.getActivationId())
                .authenticationCodeTypes(allowedAuthenticationTypes)
                .authenticationCode(request.getAuthenticationCode())
                .additionalInfo(new ArrayList<>())
                .dataString(request.getData())
                .expectedComponentLength(expectedComponentLength);

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
