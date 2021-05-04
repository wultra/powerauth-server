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
package io.getlime.security.powerauth.app.server.service;

import com.google.common.io.BaseEncoding;
import com.wultra.security.powerauth.client.model.entity.ErrorInfo;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.ActivationStatusVOConverter;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.RecoveryServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.exceptions.RollbackingServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/**
 * Default implementation of the PowerAuth 3.0 Server service.
 * The implementation of this service is divided into "behaviors"
 * responsible for individual processes.
 *
 * @see PowerAuthService
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class PowerAuthService {

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private ServiceBehaviorCatalogue behavior;

    private LocalizationProvider localizationProvider;

    private BuildProperties buildProperties;

    private final ActivationStatusVOConverter activationStatusVOConverter = new ActivationStatusVOConverter();

    // Minimum date for SQL timestamps: 01/01/1970 @ 12:00am (UTC)
    private static final Instant MIN_TIMESTAMP = Instant.ofEpochMilli(1L);

    // Maximum date for SQL timestamps: 01/01/9999 @ 12:00am (UTC)
    private static final Instant MAX_TIMESTAMP = Instant.ofEpochMilli(253370764800000L);

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(PowerAuthService.class);

    @Autowired
    public void setPowerAuthServiceConfiguration(PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    @Autowired
    public void setBehavior(ServiceBehaviorCatalogue behavior) {
        this.behavior = behavior;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    @Autowired(required = false)
    public void setBuildProperties(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    private final KeyConvertor keyConvertor = new KeyConvertor();

    public GetSystemStatusResponse getSystemStatus() {
        logger.info("GetSystemStatusRequest received");
        final GetSystemStatusResponse response = new GetSystemStatusResponse();
        response.setStatus("OK");
        response.setApplicationName(powerAuthServiceConfiguration.getApplicationName());
        response.setApplicationDisplayName(powerAuthServiceConfiguration.getApplicationDisplayName());
        response.setApplicationEnvironment(powerAuthServiceConfiguration.getApplicationEnvironment());
        if (buildProperties != null) {
            response.setVersion(buildProperties.getVersion());
            response.setBuildTime(buildProperties.getTime());
        }
        response.setTimestamp(Instant.now());
        logger.info("GetSystemStatusRequest succeeded");
        return response;
    }

    public GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) {
        logger.info("GetErrorCodeListRequest received");
        String language = request.getLanguage();
        // Check if the language is valid ISO language, use EN as default
        if (language == null || Arrays.binarySearch(Locale.getISOLanguages(), language) < 0) {
            language = Locale.ENGLISH.getLanguage();
        }
        final Locale locale = new Locale(language);
        final GetErrorCodeListResponse response = new GetErrorCodeListResponse();
        final List<String> errorCodeList = ServiceError.allCodes();
        for (String errorCode : errorCodeList) {
            ErrorInfo error = new ErrorInfo();
            error.setCode(errorCode);
            error.setValue(localizationProvider.getLocalizedErrorMessage(errorCode, locale));
            response.getErrors().add(error);
        }
        logger.info("GetErrorCodeListRequest succeeded");
        return response;
    }

    @Transactional
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method getActivationListForUser");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The applicationId can be null, in this case all applications are used
        try {
            final String userId = request.getUserId();
            final Long applicationId = request.getApplicationId();
            logger.info("GetActivationListForUserRequest received, user ID: {}, application ID: {}", userId, applicationId);
            final GetActivationListForUserResponse response = behavior.getActivationServiceBehavior().getActivationList(applicationId, userId);
            logger.info("GetActivationListForUserRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws GenericServiceException {
        if (request.getUserIds() == null || request.getUserIds().isEmpty()) {
            logger.warn("Invalid request parameter userIds in method lookupActivations");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final List<String> userIds = request.getUserIds();
            final List<Long> applicationIds = request.getApplicationIds();
            final Instant timestampLastUsedBefore;
            if (request.getTimestampLastUsedBefore() != null) {
                timestampLastUsedBefore = request.getTimestampLastUsedBefore();
            } else {
                timestampLastUsedBefore = MAX_TIMESTAMP;
            }
            final Instant timestampLastUsedAfter;
            if (request.getTimestampLastUsedAfter() != null) {
                timestampLastUsedAfter = request.getTimestampLastUsedAfter();
            } else {
                timestampLastUsedAfter = MIN_TIMESTAMP;
            }
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusVOConverter.convert(request.getActivationStatus());
            }
            final List<String> activationFlags = request.getActivationFlags();
            logger.info("LookupActivationsRequest received");
            final LookupActivationsResponse response = behavior.getActivationServiceBehavior().lookupActivations(userIds, applicationIds, timestampLastUsedBefore, timestampLastUsedAfter, activationStatus, activationFlags);
            logger.info("LookupActivationsRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws GenericServiceException {
        if (request.getActivationIds() == null || request.getActivationIds().isEmpty()) {
            logger.warn("Invalid request parameter activationIds in method updateStatusForActivations");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final List<String> activationIds = request.getActivationIds();
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusVOConverter.convert(request.getActivationStatus());
            }
            logger.info("UpdateStatusForActivationsRequest received");
            final UpdateStatusForActivationsResponse response = behavior.getActivationServiceBehavior().updateStatusForActivation(activationIds, activationStatus);
            logger.info("UpdateStatusForActivationsRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method getActivationStatus");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String challenge = request.getChallenge();
            logger.info("GetActivationStatusRequest received, activation ID: {}", activationId);
            final GetActivationStatusResponse response = behavior.getActivationServiceBehavior().getActivationStatus(activationId, challenge, keyConvertor);
            logger.info("GetActivationStatusResponse succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Transactional
    public InitActivationResponse initActivation(InitActivationRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method initActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The maxFailedCount and activationExpireTimestamp values can be null, in this case default values are used
        try {
            final String userId = request.getUserId();
            final Long applicationId = request.getApplicationId();
            final Long maxFailedCount = request.getMaxFailureCount();
            final Instant activationExpireTimestamp = request.getTimestampActivationExpire();
            final ActivationOtpValidation activationOtpValidation = request.getActivationOtpValidation();
            final String activationOtp = request.getActivationOtp();
            logger.info("InitActivationRequest received, user ID: {}, application ID: {}", userId, applicationId);
            final InitActivationResponse response = behavior.getActivationServiceBehavior().initActivation(
                    applicationId,
                    userId,
                    maxFailedCount,
                    activationExpireTimestamp,
                    activationOtpValidation,
                    activationOtp,
                    keyConvertor);
            logger.info("InitActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws GenericServiceException {
        if (request.getActivationCode() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getMac() == null || request.getEncryptedData() == null) {
            logger.warn("Invalid request parameters in prepareActivation method");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationCode = request.getActivationCode();
            final String applicationKey = request.getApplicationKey();
            final byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            final byte[] mac = BaseEncoding.base64().decode(request.getMac());
            final byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            final byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;
            final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);
            logger.info("PrepareActivationRequest received, activation code: {}", activationCode);
            final PrepareActivationResponse response = behavior.getActivationServiceBehavior().prepareActivation(activationCode, applicationKey, cryptogram, keyConvertor);
            logger.info("PrepareActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws GenericServiceException {
        if (request.getUserId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getMac() == null || request.getEncryptedData() == null) {
            logger.warn("Invalid request parameters in createActivation method");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            // Get request parameters
            final String userId = request.getUserId();
            final Instant activationExpireTimestamp = request.getTimestampActivationExpire();
            final Long maxFailedCount = request.getMaxFailureCount();
            final String applicationKey = request.getApplicationKey();
            final String activationOtp = request.getActivationOtp();
            final byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            final byte[] mac = BaseEncoding.base64().decode(request.getMac());
            final byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            final byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;
            final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);
            logger.info("CreateActivationRequest received, user ID: {}", userId);
            final CreateActivationResponse response = behavior.getActivationServiceBehavior().createActivation(
                    userId,
                    activationExpireTimestamp,
                    maxFailedCount,
                    applicationKey,
                    cryptogram,
                    activationOtp,
                    keyConvertor
            );
            logger.info("CreateActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    private VerifySignatureResponse verifySignatureImplNonTransaction(VerifySignatureRequest request, Map<String, Object> additionalInfo) throws GenericServiceException {
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
        return behavior.getOnlineSignatureServiceBehavior().verifySignature(activationId, signatureType, signature, signatureVersion, additionalInfo, dataString, applicationKey, forcedSignatureVersion, keyConvertor);
    }

    @Transactional
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getData() == null
                || request.getSignature() == null || request.getSignatureType() == null || request.getSignatureVersion() == null) {
            logger.warn("Invalid request parameters in method verifySignature");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("VerifySignatureRequest received, activation ID: {}", request.getActivationId());
            final VerifySignatureResponse response = this.verifySignatureImplNonTransaction(request, new HashMap<>());
            logger.info("VerifySignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null) {
            logger.warn("Invalid request parameters in method createPersonalizedOfflineSignaturePayload");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();
            logger.info("CreatePersonalizedOfflineSignaturePayloadRequest received, activation ID: {}", activationId);
            final CreatePersonalizedOfflineSignaturePayloadResponse response = behavior.getOfflineSignatureServiceBehavior().createPersonalizedOfflineSignaturePayload(activationId, data, keyConvertor);
            logger.info("CreatePersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        if (request.getData() == null) {
            logger.warn("Invalid request parameter data in method createNonPersonalizedOfflineSignaturePayload");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final long applicationId = request.getApplicationId();
            final String data = request.getData();
            logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest received, application ID: {}", applicationId);
            final CreateNonPersonalizedOfflineSignaturePayloadResponse response = behavior.getOfflineSignatureServiceBehavior().createNonPersonalizedOfflineSignaturePayload(applicationId, data, keyConvertor);
            logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null || request.getSignature() == null) {
            logger.warn("Invalid request parameters in method verifyOfflineSignature");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String data = request.getData();
            final String signature = request.getSignature();
            final List<SignatureType> allowedSignatureTypes = new ArrayList<>();
            // The order of signature types is important. PowerAuth server logs first found signature type
            // as used signature type in case signature verification fails. In case the POSSESSION_BIOMETRY signature
            // type is allowed, additional info in signature audit contains flag BIOMETRY_ALLOWED.
            allowedSignatureTypes.add(SignatureType.POSSESSION_KNOWLEDGE);
            if (request.isAllowBiometry()) {
                allowedSignatureTypes.add(SignatureType.POSSESSION_BIOMETRY);
            }
            logger.info("VerifyOfflineSignatureRequest received, activation ID: {}", activationId);
            final VerifyOfflineSignatureResponse response = behavior.getOfflineSignatureServiceBehavior().verifyOfflineSignature(activationId, allowedSignatureTypes, signature, new HashMap<>(), data, keyConvertor);
            logger.info("VerifyOfflineSignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method commitActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            final String activationOtp = request.getActivationOtp();
            logger.info("UpdateActivationOtpRequest received, activation ID: {}", activationId);
            final UpdateActivationOtpResponse response = behavior.getActivationServiceBehavior().updateActivationOtp(activationId, externalUserId, activationOtp);
            logger.info("UpdateActivationOtpRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method commitActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            final String activationOtp = request.getActivationOtp();
            logger.info("CommitActivationRequest received, activation ID: {}", activationId);
            final CommitActivationResponse response = behavior.getActivationServiceBehavior().commitActivation(activationId, externalUserId, activationOtp);
            logger.info("CommitActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method removeActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            Boolean revokeRecoveryCodes = request.getRevokeRecoveryCodes();
            if (revokeRecoveryCodes == null) {
                // The default value is false for revokeRecoveryCodes
                revokeRecoveryCodes = false;
            }
            logger.info("RemoveActivationRequest received, activation ID: {}, revoke recovery codes: {}", activationId, revokeRecoveryCodes);
            final RemoveActivationResponse response = behavior.getActivationServiceBehavior().removeActivation(activationId, externalUserId, revokeRecoveryCodes);
            logger.info("RemoveActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method blockActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String reason = request.getReason();
            final String externalUserId = request.getExternalUserId();
            logger.info("BlockActivationRequest received, activation ID: {}", activationId);
            final BlockActivationResponse response = behavior.getActivationServiceBehavior().blockActivation(activationId, reason, externalUserId);
            logger.info("BlockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method unblockActivation");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String externalUserId = request.getExternalUserId();
            logger.info("UnblockActivationRequest received, activation ID: {}", activationId);
            final UnblockActivationResponse response = behavior.getActivationServiceBehavior().unblockActivation(activationId, externalUserId);
            logger.info("UnblockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Transactional
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getSignature() == null
                || request.getSignatureType() == null || request.getSignatureVersion() == null || request.getSignedData() == null
                || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method vaultUnlock");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            // Get request data
            final String activationId = request.getActivationId();
            final String applicationKey = request.getApplicationKey();
            final String signature = request.getSignature();
            final SignatureType signatureType = request.getSignatureType();
            final String signatureVersion = request.getSignatureVersion();
            final String signedData = request.getSignedData();
            final byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            final byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            final byte[] mac = BaseEncoding.base64().decode(request.getMac());
            final byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;

            logger.info("VaultUnlockRequest received, activation ID: {}", activationId);

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

            // Convert received ECIES request data to cryptogram
            final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);

            final VaultUnlockResponse response = behavior.getVaultUnlockServiceBehavior().unlockVault(activationId, applicationKey,
                    signature, signatureType, signatureVersion, signedData, cryptogram, keyConvertor);
            logger.info("VaultUnlockRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null || request.getSignature() == null) {
            logger.warn("Invalid request parameters in method verifyECDSASignature");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final String signedData = request.getData();
            final String signature  = request.getSignature();
            logger.info("VerifyECDSASignatureRequest received, activation ID: {}", activationId);
            final boolean matches = behavior.getAsymmetricSignatureServiceBehavior().verifyECDSASignature(activationId, signedData, signature, keyConvertor);
            final VerifyECDSASignatureResponse response = new VerifyECDSASignatureResponse();
            response.setSignatureValid(matches);
            logger.info("VerifyECDSASignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method getSignatureAuditLog");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {

            final String userId = request.getUserId();
            final Long applicationId = request.getApplicationId();
            final Instant startingDate = request.getTimestampFrom();
            final Instant endingDate = request.getTimestampTo();

            logger.info("SignatureAuditRequest received, user ID: {}, application ID: {}", userId, applicationId);
            final SignatureAuditResponse response = behavior.getAuditingServiceBehavior().getSignatureAuditLog(userId, applicationId, startingDate, endingDate);
            logger.info("SignatureAuditRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Transactional
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method getActivationHistory");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            final String activationId = request.getActivationId();
            final Instant startingDate = request.getTimestampFrom();
            final Instant endingDate = request.getTimestampTo();
            logger.info("ActivationHistoryRequest received, activation ID: {}", activationId);
            final ActivationHistoryResponse response = behavior.getActivationHistoryServiceBehavior().getActivationHistory(activationId, startingDate, endingDate);
            logger.info("ActivationHistoryRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetApplicationListResponse getApplicationList() throws GenericServiceException {
        try {
            logger.info("GetApplicationListRequest received");
            final GetApplicationListResponse response = behavior.getApplicationServiceBehavior().getApplicationList();
            logger.info("GetApplicationListRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws GenericServiceException {
        try {
            final GetApplicationDetailResponse response;
            if (request.getApplicationId() != null && request.getApplicationName() == null) {
                logger.info("GetApplicationDetailRequest received, application ID: {}", request.getApplicationId());
                response = behavior.getApplicationServiceBehavior().getApplicationDetail(request.getApplicationId());
            } else if (request.getApplicationName() != null && request.getApplicationId() == null) {
                logger.info("GetApplicationDetailRequest received, application name: '{}'", request.getApplicationName());
                response = behavior.getApplicationServiceBehavior().getApplicationDetailByName(request.getApplicationName());
            } else {
                // Rollback is not required, database is not used for writing
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            logger.info("GetApplicationDetailRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null) {
            logger.warn("Invalid request parameter applicationKey in method lookupApplicationByAppKey");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("LookupApplicationByAppKeyRequest received");
            final LookupApplicationByAppKeyResponse response = behavior.getApplicationServiceBehavior().lookupApplicationByAppKey(request.getApplicationKey());
            logger.info("LookupApplicationByAppKeyRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws GenericServiceException {
        if (request.getApplicationName() == null) {
            logger.warn("Invalid request parameter applicationName in method createApplication");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateApplicationRequest received, application name: {}", request.getApplicationName());
            final CreateApplicationResponse response = behavior.getApplicationServiceBehavior().createApplication(request.getApplicationName(), keyConvertor);
            logger.info("CreateApplicationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws GenericServiceException {
        if (request.getApplicationVersionName() == null) {
            logger.warn("Invalid request parameter applicationVersionName in method createApplicationVersion");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateApplicationVersionRequest received, application ID: {}, application version name: {}", request.getApplicationId(), request.getApplicationVersionName());
            final CreateApplicationVersionResponse response = behavior.getApplicationServiceBehavior().createApplicationVersion(request.getApplicationId(), request.getApplicationVersionName());
            logger.info("CreateApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("UnsupportApplicationVersionRequest received, application version ID: {}", request.getApplicationVersionId());
            final UnsupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().unsupportApplicationVersion(request.getApplicationVersionId());
            logger.info("UnsupportApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("SupportApplicationVersionRequest received, application version ID: {}", request.getApplicationVersionId());
            final SupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().supportApplicationVersion(request.getApplicationVersionId());
            logger.info("SupportApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws GenericServiceException {
        if (request.getName() == null) {
            logger.warn("Invalid request parameter name in method createIntegration");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateIntegrationRequest received, name: {}", request.getName());
            final CreateIntegrationResponse response = behavior.getIntegrationBehavior().createIntegration(request);
            logger.info("CreateIntegrationRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetIntegrationListResponse getIntegrationList() throws GenericServiceException {
        try {
            logger.info("GetIntegrationListRequest received");
            final GetIntegrationListResponse response = behavior.getIntegrationBehavior().getIntegrationList();
            logger.info("GetIntegrationListRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws GenericServiceException {
        try {
            logger.info("RemoveIntegrationRequest received, id: {}", request.getId());
            final RemoveIntegrationResponse response = behavior.getIntegrationBehavior().removeIntegration(request);
            logger.info("RemoveIntegrationRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {
        if (request.getName() == null) {
            logger.warn("Invalid request parameter name in method createCallbackUrl");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateCallbackUrlRequest received, name: {}", request.getName());
            final CreateCallbackUrlResponse response = behavior.getCallbackUrlBehavior().createCallbackUrl(request);
            logger.info("CreateCallbackUrlRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws Exception {
        if (request.getId() == null || request.getApplicationId() <= 0 || request.getName() == null || request.getAttributes() == null) {
            logger.warn("Invalid request in method updateCallbackUrl");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("UpdateCallbackUrlRequest received, name: {}", request.getName());
            final UpdateCallbackUrlResponse response = behavior.getCallbackUrlBehavior().updateCallbackUrl(request);
            logger.info("UpdateCallbackUrlRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws GenericServiceException {
        try {
            logger.info("GetCallbackUrlListRequest received, application ID: {}", request.getApplicationId());
            final GetCallbackUrlListResponse response = behavior.getCallbackUrlBehavior().getCallbackUrlList(request);
            logger.info("GetCallbackUrlListRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws GenericServiceException {
        try {
            logger.info("RemoveCallbackUrlRequest received, id: {}", request.getId());
            final RemoveCallbackUrlResponse response = behavior.getCallbackUrlBehavior().removeCallbackUrl(request);
            logger.info("RemoveCallbackUrlRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateTokenResponse createToken(CreateTokenRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method createToken");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateTokenRequest received, activation ID: {}", request.getActivationId());
            final CreateTokenResponse response = behavior.getTokenBehavior().createToken(request, keyConvertor);
            logger.info("CreateTokenRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws GenericServiceException {
        if (request.getTokenId() == null || request.getNonce() == null || request.getTokenDigest() == null) {
            logger.warn("Invalid request parameters in method validateToken");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // Verify the token timestamp validity
        if (request.getTimestamp() < System.currentTimeMillis() - powerAuthServiceConfiguration.getTokenTimestampValidityInMilliseconds()) {
            logger.warn("Invalid request - token timestamp is too old for token ID: {}", request.getTokenId());
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.TOKEN_TIMESTAMP_TOO_OLD);
        }
        try {
            logger.info("ValidateTokenRequest received, token ID: {}", request.getTokenId());
            final ValidateTokenResponse response = behavior.getTokenBehavior().validateToken(request);
            logger.info("ValidateTokenRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws GenericServiceException {
        if (request.getTokenId() == null) {
            logger.warn("Invalid request parameter tokenId in method removeToken");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RemoveTokenRequest received, token ID: {}", request.getTokenId());
            final RemoveTokenResponse response = behavior.getTokenBehavior().removeToken(request);
            logger.info("RemoveTokenRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null) {
            logger.warn("Invalid request parameters in method getEciesDecryptor");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The activationId value can be null in case the decryptor is used in application scope
        try {
            logger.info("GetEciesDecryptorRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            final GetEciesDecryptorResponse response = behavior.getEciesEncryptionBehavior().getEciesDecryptorParameters(request);
            logger.info("GetEciesDecryptorRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method startUpgrade");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("StartUpgradeRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            final StartUpgradeResponse response = behavior.getUpgradeServiceBehavior().startUpgrade(request);
            logger.info("StartUpgradeRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null) {
            logger.warn("Invalid request parameters in method commitUpgrade");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CommitUpgradeRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            final CommitUpgradeResponse response = behavior.getUpgradeServiceBehavior().commitUpgrade(request);
            logger.info("CommitUpgradeRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L || request.getUserId() == null || request.getPukCount() < 1 || request.getPukCount() > RecoveryServiceBehavior.PUK_COUNT_MAX) {
            logger.warn("Invalid request parameters in method createRecoveryCode");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateRecoveryCodeRequest received, application ID: {}, user ID: {}", request.getApplicationId(), request.getUserId());
            final CreateRecoveryCodeResponse response = behavior.getRecoveryServiceBehavior().createRecoveryCode(request, keyConvertor);
            logger.info("CreateRecoveryCodeRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null
                || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method confirmRecoveryCode");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("ConfirmRecoveryCodeRequest received, activation ID: {}, application key: {}", request.getActivationId(), request.getApplicationKey());
            final ConfirmRecoveryCodeResponse response = behavior.getRecoveryServiceBehavior().confirmRecoveryCode(request, keyConvertor);
            logger.info("ConfirmRecoveryCodeRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws GenericServiceException {
        if (request.getApplicationId() == null && request.getUserId() == null && request.getActivationId() == null) {
            logger.warn("Invalid request parameters in method lookupRecoveryCodes");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("LookupRecoveryCodesRequest received, application ID: {}, user ID: {}, activation ID: {}", request.getApplicationId(), request.getUserId(), request.getActivationId());
            final LookupRecoveryCodesResponse response = behavior.getRecoveryServiceBehavior().lookupRecoveryCodes(request);
            logger.info("LookupRecoveryCodesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws GenericServiceException {
        if (request.getRecoveryCodeIds() == null || request.getRecoveryCodeIds().isEmpty()) {
            logger.warn("Invalid request parameters in method revokeRecoveryCodes");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RevokeRecoveryCodesRequest received, recovery code IDs: {}", request.getRecoveryCodeIds());
            final RevokeRecoveryCodesResponse response = behavior.getRecoveryServiceBehavior().revokeRecoveryCodes(request);
            logger.info("RevokeRecoveryCodesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional(rollbackFor = {RuntimeException.class, RollbackingServiceException.class})
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws GenericServiceException {
        if (request.getRecoveryCode() == null || request.getPuk() == null || request.getApplicationKey() == null
            || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method createActivationUsingRecoveryCode");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RecoveryCodeActivationRequest received, recovery code: {}, application key: {}", request.getRecoveryCode(), request.getApplicationKey());
            final RecoveryCodeActivationResponse response = behavior.getActivationServiceBehavior().createActivationUsingRecoveryCode(request, keyConvertor);
            logger.info("RecoveryCodeActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method getRecoveryConfig");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("GetRecoveryConfigRequest received, application ID: {}", request.getApplicationId());
            final GetRecoveryConfigResponse response = behavior.getRecoveryServiceBehavior().getRecoveryConfig(request);
            logger.info("GetRecoveryConfigRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method updateRecoveryConfig");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("UpdateRecoveryConfigRequest received, application ID: {}", request.getApplicationId());
            final UpdateRecoveryConfigResponse response = behavior.getRecoveryServiceBehavior().updateRecoveryConfig(request, keyConvertor);
            logger.info("UpdateRecoveryConfigRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method listActivationFlags");
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("ListActivationFlagsRequest received, activation ID: {}", request.getActivationId());
            final String activationId = request.getActivationId();
            final ListActivationFlagsResponse response = behavior.getActivationFlagsServiceBehavior().listActivationFlags(activationId);
            logger.info("ListActivationFlagsRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method addActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getActivationFlags() == null || request.getActivationFlags().isEmpty()) {
            logger.warn("Invalid request parameter activationFlags in method addActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("addActivationFlagsRequest received, activation ID: {}", request.getActivationId());
            final String activationId = request.getActivationId();
            final List<String> flags = request.getActivationFlags();
            final AddActivationFlagsResponse response = behavior.getActivationFlagsServiceBehavior().addActivationFlags(activationId, flags);
            logger.info("addActivationFlagsRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method updateActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getActivationFlags() == null || request.getActivationFlags().isEmpty()) {
            logger.warn("Invalid request parameter activationFlags in method updateActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("UpdateActivationFlagsRequest received, activation ID: {}", request.getActivationId());
            final String activationId = request.getActivationId();
            final List<String> flags = request.getActivationFlags();
            final UpdateActivationFlagsResponse response = behavior.getActivationFlagsServiceBehavior().updateActivationFlags(activationId, flags);
            logger.info("UpdateActivationFlagsRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method removeActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getActivationFlags() == null || request.getActivationFlags().isEmpty()) {
            logger.warn("Invalid request parameter activationFlags in method removeActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RemoveActivationFlagsRequest received, activation ID: {}", request.getActivationId());
            final String activationId = request.getActivationId();
            final List<String> flags = request.getActivationFlags();
            final RemoveActivationFlagsResponse response = behavior.getActivationFlagsServiceBehavior().removeActivationFlags(activationId, flags);
            logger.info("RemoveActivationFlagsRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws Exception {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method listApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("ListApplicationRolesRequest received, application ID: {}", request.getApplicationId());
            final long applicationId = request.getApplicationId();
            final ListApplicationRolesResponse response = behavior.getApplicationRolesServiceBehavior().listApplicationRoles(applicationId);
            logger.info("ListApplicationRolesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws Exception {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method addApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getApplicationRoles() == null || request.getApplicationRoles().isEmpty()) {
            logger.warn("Invalid request parameter applicationRoles in method addApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("AddApplicationRolesRequest received, application ID: {}", request.getApplicationId());
            final long applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            final AddApplicationRolesResponse response = behavior.getApplicationRolesServiceBehavior().addApplicationRoles(applicationId, applicationRoles);
            logger.info("AddApplicationRolesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws Exception {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method updateApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getApplicationRoles() == null || request.getApplicationRoles().isEmpty()) {
            logger.warn("Invalid request parameter applicationRoles in method updateApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("UpdateApplicationRolesRequest received, application ID: {}", request.getApplicationId());
            final long applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            final UpdateApplicationRolesResponse response = behavior.getApplicationRolesServiceBehavior().updateApplicationRoles(applicationId, applicationRoles);
            logger.info("UpdateApplicationRolesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws Exception {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method removeApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (request.getApplicationRoles() == null || request.getApplicationRoles().isEmpty()) {
            logger.warn("Invalid request parameter applicationRoles in method removeApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RemoveApplicationRolesRequest received, application ID: {}", request.getApplicationId());
            final long applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            final RemoveApplicationRolesResponse response = behavior.getApplicationRolesServiceBehavior().removeApplicationRoles(applicationId, applicationRoles);
            logger.info("RemoveApplicationRolesRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationDetailResponse createOperation(OperationCreateRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("CreateOperationRequest received, template name: {}, user ID: {}, application ID: {}", request.getTemplateName(), request.getUserId(), request.getApplicationId());
            final OperationDetailResponse response = behavior.getOperationBehavior().createOperation(request);
            logger.info("CreateOperationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationDetailRequest received, operation ID: {}", request.getOperationId());
            final OperationDetailResponse response = behavior.getOperationBehavior().getOperation(request);
            logger.info("OperationDetailRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationListResponse findPendingOperationsForUser(OperationListForUserRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationListForUserRequest received, user ID: {}, appId: {}", request.getUserId(), request.getApplicationId());
            final OperationListResponse response = behavior.getOperationBehavior().findPendingOperationsForUser(request);
            logger.info("OperationListForUserRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationListResponse findAllOperationsForUser(OperationListForUserRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationListForUserRequest received, user ID: {}, appId: {}", request.getUserId(), request.getApplicationId());
            final OperationListResponse response = behavior.getOperationBehavior().findAllOperationsForUser(request);
            logger.info("OperationListForUserRequest succeeded");
            return response;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationDetailResponse cancelOperation(OperationCancelRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationCancelRequest received, operation ID: {}", request.getOperationId());
            final OperationDetailResponse response = behavior.getOperationBehavior().cancelOperation(request);
            logger.info("OperationCancelRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationUserActionResponse approveOperation(OperationApproveRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationApproveRequest received, operation ID: {}, user ID: {}, application ID: {}, signatureType: {}",
                    request.getOperationId(),
                    request.getUserId(),
                    request.getApplicationId(),
                    request.getSignatureType()
            );
            final OperationUserActionResponse response = behavior.getOperationBehavior().attemptApproveOperation(request);
            logger.info("OperationApproveRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationUserActionResponse rejectOperation(OperationRejectRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationRejectRequest received, operation ID: {}, user ID: {}, application ID: {}",
                    request.getOperationId(),
                    request.getUserId(),
                    request.getApplicationId()
            );
            final OperationUserActionResponse response = behavior.getOperationBehavior().rejectOperation(request);
            logger.info("OperationRejectRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Transactional
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws Exception {
        // TODO: Validators
        try {
            logger.info("OperationFailApprovalRequest received, operation ID: {}", request.getOperationId());
            final OperationUserActionResponse response = behavior.getOperationBehavior().failApprovalOperation(request);
            logger.info("OperationFailApprovalRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException | Error ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

}
