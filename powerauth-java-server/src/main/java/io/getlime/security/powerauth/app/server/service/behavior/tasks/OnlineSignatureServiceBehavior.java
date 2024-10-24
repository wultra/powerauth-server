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

import com.wultra.security.powerauth.client.model.entity.KeyValue;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationVersionRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.signature.OnlineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.app.server.service.persistence.ActivationQueryService;
import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class OnlineSignatureServiceBehavior {

    private final SignatureSharedServiceBehavior signatureSharedServiceBehavior;
    private final ActivationQueryService activationQueryService;
    private final LocalizationProvider localizationProvider;
    private final ApplicationVersionRepository applicationVersionRepository;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();
    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Verify signature for given activation and provided data in online mode. Log every validation attempt in the audit log.
     *
     * @param request Signature verification request.
     * @return Response with the signature validation result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    @Transactional
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request, List<KeyValue> additionalInfo)
            throws GenericServiceException {
        try {
            // Get request data
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String dataString = request.getData();
            final String signature = request.getSignature();
            final String signatureVersion = request.getSignatureVersion();
            final SignatureType signatureType = request.getSignatureType();
            // Forced signature version during upgrade, currently only version 3 is supported
            Integer forcedSignatureVersion = null;
            if (request.getForcedSignatureVersion() != null && request.getForcedSignatureVersion() == 3) {
                forcedSignatureVersion = 3;
            }

            if (activationId == null || applicationKey == null || dataString == null
                    || signature == null || signatureType == null || signatureVersion == null) {
                logger.warn("Invalid request parameters in method verifySignature");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            return verifySignatureImpl(activationId, signatureType, signature, signatureVersion, additionalInfo, dataString, applicationKey, forcedSignatureVersion, keyConvertor);
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
        }  catch (GenericServiceException ex) {
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
     * @param activationId Activation ID.
     * @param signatureType Signature type to use for signature verification.
     * @param signature Signature.
     * @param signatureVersion Signature version.
     * @param additionalInfo Additional information related to signature verification.
     * @param dataString Signature data.
     * @param applicationKey Application key.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     * @param keyConversionUtilities Key convertor.
     * @return Verify offline signature response.
     * @throws InvalidKeySpecException In case a key specification is invalid.
     * @throws InvalidKeyException In case a key is invalid.
     * @throws GenericServiceException In case of a business logic error.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private VerifySignatureResponse verifySignatureImpl(String activationId, SignatureType signatureType, String signature, String signatureVersion, List<KeyValue> additionalInfo,
                                                        String dataString, String applicationKey, Integer forcedSignatureVersion, KeyConvertor keyConversionUtilities)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        // Prepare current timestamp in advance
        final Date currentTimestamp = new Date();

        // Fetch related activation
        final Optional<ActivationRecordEntity> activationOptional = activationQueryService.findActivationForUpdate(activationId);
        if (activationOptional.isEmpty()) {
            return invalidStateResponse(activationId, ActivationStatus.REMOVED);
        }
        final ActivationRecordEntity activation = activationOptional.get();

        final Long applicationId = activation.getApplication().getRid();

        // Convert signature version to expected signature format.
        final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(signatureVersion);
        final SignatureConfiguration signatureConfiguration = SignatureConfiguration.forFormat(signatureFormat);

        // Check the activation - application relationship and version support
        final ApplicationVersionEntity applicationVersion = applicationVersionRepository.findByApplicationKey(applicationKey);

        if (applicationVersion == null || !applicationVersion.getSupported() || !Objects.equals(applicationVersion.getApplication().getRid(), applicationId)) {
            logger.warn("Application version is incorrect, application key: {}", applicationKey);
            // Get the data and append application KEY in this case, just for auditing reasons
            final byte[] data = (dataString + "&" + applicationKey).getBytes(StandardCharsets.UTF_8);
            final SignatureData signatureData = new SignatureData(data, signature, signatureConfiguration, signatureVersion, additionalInfo, forcedSignatureVersion);
            final OnlineSignatureRequest signatureRequest = new OnlineSignatureRequest(signatureData, signatureType);
            signatureSharedServiceBehavior.handleInvalidApplicationVersion(activation, signatureRequest, currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());
        }

        final byte[] data = (dataString + "&" + applicationVersion.getApplicationSecret()).getBytes(StandardCharsets.UTF_8);
        final SignatureData signatureData = new SignatureData(data, signature, signatureConfiguration, signatureVersion, additionalInfo, forcedSignatureVersion);
        final OnlineSignatureRequest signatureRequest = new OnlineSignatureRequest(signatureData, signatureType);

        if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

            // Double-check that there are at least some remaining attempts
            if (activation.getFailedAttempts() >= activation.getMaxFailedAttempts()) { // ... otherwise, the activation should be already blocked
                signatureSharedServiceBehavior.handleInactiveActivationWithMismatchSignature(activation, signatureRequest, currentTimestamp);
                return invalidStateResponse(activationId, activation.getActivationStatus());
            }

            final SignatureResponse verificationResponse = signatureSharedServiceBehavior.verifySignature(activation, signatureRequest, keyConversionUtilities);

            // Check if the signature is valid
            if (verificationResponse.isSignatureValid()) {

                signatureSharedServiceBehavior.handleValidSignature(activation, verificationResponse, signatureRequest, currentTimestamp);

                return validSignatureResponse(activation, verificationResponse.getUsedSignatureType());

            } else {

                signatureSharedServiceBehavior.handleInvalidSignature(activation, verificationResponse, signatureRequest, currentTimestamp);

                return invalidSignatureResponse(activation, signatureRequest);

            }
        } else {

            signatureSharedServiceBehavior.handleInactiveActivationSignature(activation, signatureRequest, currentTimestamp);

            // return the data
            return invalidStateResponse(activationId, activation.getActivationStatus());

        }

    }

    /**
     * Generates an invalid signature response when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     * @param activationId Activation ID.
     * @param activationStatus Activation status.
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidStateResponse(String activationId, ActivationStatus activationStatus) {
        final VerifySignatureResponse response = new VerifySignatureResponse();
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
    private VerifySignatureResponse validSignatureResponse(ActivationRecordEntity activation, SignatureType usedSignatureType) {
        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // Return the data
        final VerifySignatureResponse response = new VerifySignatureResponse();
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
     * @param signatureRequest Signature request.
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidSignatureResponse(ActivationRecordEntity activation, OnlineSignatureRequest signatureRequest) {
        // Calculate remaining attempts
        final long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        // Extract application ID and application roles
        final String applicationId = activation.getApplication().getId();
        final List<String> applicationRoles = activation.getApplication().getRoles();
        final List<String> activationFlags = activation.getFlags();

        // return the data
        final VerifySignatureResponse response = new VerifySignatureResponse();
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
        response.setSignatureType(signatureRequest.getSignatureType());
        return response;
    }

}
