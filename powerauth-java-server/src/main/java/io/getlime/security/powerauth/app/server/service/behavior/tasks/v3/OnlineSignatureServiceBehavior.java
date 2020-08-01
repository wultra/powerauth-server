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

import com.wultra.security.powerauth.client.v3.KeyValueMap;
import com.wultra.security.powerauth.client.v3.SignatureType;
import com.wultra.security.powerauth.client.v3.VerifySignatureResponse;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationVersionEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.signature.OnlineSignatureRequest;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureData;
import io.getlime.security.powerauth.app.server.service.model.signature.SignatureResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureFormat;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Behavior class implementing the signature validation related processes. The class separates the
 * logic from the main service class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class OnlineSignatureServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final SignatureSharedServiceBehavior signatureSharedServiceBehavior;
    private final LocalizationProvider localizationProvider;

    // Prepare converters
    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(OnlineSignatureServiceBehavior.class);

    @Autowired
    public OnlineSignatureServiceBehavior(RepositoryCatalogue repositoryCatalogue, SignatureSharedServiceBehavior signatureSharedServiceBehavior, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.signatureSharedServiceBehavior = signatureSharedServiceBehavior;
        this.localizationProvider = localizationProvider;
    }

    /**
     * Verify signature for given activation and provided data in online mode. Log every validation attempt in the audit log.
     *
     * @param activationId           Activation ID.
     * @param signatureType          Provided signature type.
     * @param signature              Provided signature.
     * @param signatureVersion       Version of signature.
     * @param additionalInfo         Additional information about operation.
     * @param dataString             String with data used to compute the signature.
     * @param applicationKey         Associated application key.
     * @param forcedSignatureVersion Forced signature version during upgrade.
     * @param keyConversionUtilities Conversion utility class.
     * @return Response with the signature validation result object.
     * @throws GenericServiceException In case server private key decryption fails.
     */
    public VerifySignatureResponse verifySignature(String activationId, SignatureType signatureType, String signature, String signatureVersion, KeyValueMap additionalInfo,
                                                   String dataString, String applicationKey, Integer forcedSignatureVersion, KeyConvertor keyConversionUtilities)
            throws GenericServiceException {
        try {
            return verifySignatureImpl(activationId, signatureType, signature, signatureVersion, additionalInfo, dataString, applicationKey, forcedSignatureVersion, keyConversionUtilities);
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
    private VerifySignatureResponse verifySignatureImpl(String activationId, SignatureType signatureType, String signature, String signatureVersion, KeyValueMap additionalInfo,
                                                        String dataString, String applicationKey, Integer forcedSignatureVersion, KeyConvertor keyConversionUtilities)
            throws InvalidKeySpecException, InvalidKeyException, GenericServiceException, GenericCryptoException, CryptoProviderException {
        // Prepare current timestamp in advance
        Date currentTimestamp = new Date();

        // Fetch related activation
        ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithLock(activationId);

        // Only validate signature for existing ACTIVE activation records
        if (activation != null) {

            Long applicationId = activation.getApplication().getId();

            // Convert signature version to expected signature format.
            final PowerAuthSignatureFormat signatureFormat = PowerAuthSignatureFormat.getFormatForSignatureVersion(signatureVersion);

            // Check the activation - application relationship and version support
            ApplicationVersionEntity applicationVersion = repositoryCatalogue.getApplicationVersionRepository().findByApplicationKey(applicationKey);

            if (applicationVersion == null || !applicationVersion.getSupported() || !Objects.equals(applicationVersion.getApplication().getId(), applicationId)) {
                logger.warn("Application version is incorrect, application key: {}", applicationKey);
                // Get the data and append application KEY in this case, just for auditing reasons
                byte[] data = (dataString + "&" + applicationKey).getBytes(StandardCharsets.UTF_8);
                SignatureData signatureData = new SignatureData(data, signature, signatureFormat, signatureVersion, additionalInfo, forcedSignatureVersion);
                OnlineSignatureRequest signatureRequest = new OnlineSignatureRequest(signatureData, signatureType);
                signatureSharedServiceBehavior.handleInvalidApplicationVersion(activation, signatureRequest, currentTimestamp);

                // return the data
                return invalidStateResponse(activationId, activation.getActivationStatus());
            }

            byte[] data = (dataString + "&" + applicationVersion.getApplicationSecret()).getBytes(StandardCharsets.UTF_8);
            SignatureData signatureData = new SignatureData(data, signature, signatureFormat, signatureVersion, additionalInfo, forcedSignatureVersion);
            OnlineSignatureRequest signatureRequest = new OnlineSignatureRequest(signatureData, signatureType);

            if (activation.getActivationStatus() == ActivationStatus.ACTIVE) {

                SignatureResponse verificationResponse = signatureSharedServiceBehavior.verifySignature(activation, signatureRequest, keyConversionUtilities);

                // Check if the signature is valid
                if (verificationResponse.isSignatureValid()) {

                    signatureSharedServiceBehavior.handleValidSignature(activation, verificationResponse, signatureRequest, currentTimestamp);

                    return validSignatureResponse(activation,  verificationResponse.getUsedSignatureType());

                } else {

                    signatureSharedServiceBehavior.handleInvalidSignature(activation, verificationResponse, signatureRequest, currentTimestamp);

                    return invalidSignatureResponse(activation, signatureRequest);

                }
            } else {

                signatureSharedServiceBehavior.handleInactiveActivationSignature(activation, signatureRequest, currentTimestamp);

                // return the data
                return invalidStateResponse(activationId, activation.getActivationStatus());

            }
        } else { // Activation does not exist

            return invalidStateResponse(activationId, ActivationStatus.REMOVED);

        }
    }

    /**
     * Generates an invalid signature reponse when state is invalid (invalid applicationVersion, activation is not active, activation does not exist, etc.).
     * @param activationId Activation ID.
     * @param activationStatus Activation status.
     * @return Invalid signature response.
     */
    private VerifySignatureResponse invalidStateResponse(String activationId, ActivationStatus activationStatus) {
        VerifySignatureResponse response = new VerifySignatureResponse();
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
        Long applicationId = activation.getApplication().getId();
        List<String> applicationRoles = activation.getApplication().getRoles();

        // Return the data
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(true);
        response.setActivationStatus(activationStatusConverter.convert(ActivationStatus.ACTIVE));
        response.setBlockedReason(null);
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(activation.getMaxFailedAttempts()));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
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
        long remainingAttempts = (activation.getMaxFailedAttempts() - activation.getFailedAttempts());
        // Extract application ID and application roles
        Long applicationId = activation.getApplication().getId();
        List<String> applicationRoles = activation.getApplication().getRoles();

        // return the data
        VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(false);
        response.setActivationStatus(activationStatusConverter.convert(activation.getActivationStatus()));
        response.setBlockedReason(activation.getBlockedReason());
        response.setActivationId(activation.getActivationId());
        response.setRemainingAttempts(BigInteger.valueOf(remainingAttempts));
        response.setUserId(activation.getUserId());
        response.setApplicationId(applicationId);
        response.getApplicationRoles().addAll(applicationRoles);
        // In case multiple signature types are used, use the first one as signature type
        response.setSignatureType(signatureRequest.getSignatureType());
        return response;
    }

}
