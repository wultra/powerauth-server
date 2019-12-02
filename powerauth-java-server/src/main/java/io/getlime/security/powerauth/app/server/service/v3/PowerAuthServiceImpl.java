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
package io.getlime.security.powerauth.app.server.service.v3;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.converter.v3.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.RecoveryServiceBehavior;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.v3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

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
@Component("powerAuthServiceImplV3")
public class PowerAuthServiceImpl implements PowerAuthService {

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private ServiceBehaviorCatalogue behavior;

    private LocalizationProvider localizationProvider;

    private BuildProperties buildProperties;

    private final ActivationStatusConverter activationStatusConverter = new ActivationStatusConverter();

    // Prepare logger
    private static final Logger logger = LoggerFactory.getLogger(PowerAuthServiceImpl.class);

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

    private final CryptoProviderUtil keyConversionUtilities = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    @Override
    public GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws Exception {
        logger.info("GetSystemStatusRequest received");
        GetSystemStatusResponse response = new GetSystemStatusResponse();
        response.setStatus("OK");
        response.setApplicationName(powerAuthServiceConfiguration.getApplicationName());
        response.setApplicationDisplayName(powerAuthServiceConfiguration.getApplicationDisplayName());
        response.setApplicationEnvironment(powerAuthServiceConfiguration.getApplicationEnvironment());
        if (buildProperties != null) {
            response.setVersion(buildProperties.getVersion());
            response.setBuildTime(XMLGregorianCalendarConverter.convertFrom(Date.from(buildProperties.getTime())));
        }
        response.setTimestamp(XMLGregorianCalendarConverter.convertFrom(new Date()));
        logger.info("GetSystemStatusRequest succeeded");
        return response;
    }

    @Override
    public GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) {
        logger.info("GetErrorCodeListRequest received");
        String language = request.getLanguage();
        // Check if the language is valid ISO language, use EN as default
        if (Arrays.binarySearch(Locale.getISOLanguages(), language) < 0) {
            language = Locale.ENGLISH.getLanguage();
        }
        Locale locale = new Locale(language);
        GetErrorCodeListResponse response = new GetErrorCodeListResponse();
        List<String> errorCodeList = ServiceError.allCodes();
        for (String errorCode : errorCodeList) {
            GetErrorCodeListResponse.Errors error = new GetErrorCodeListResponse.Errors();
            error.setCode(errorCode);
            error.setValue(localizationProvider.getLocalizedErrorMessage(errorCode, locale));
            response.getErrors().add(error);
        }
        logger.info("GetErrorCodeListRequest succeeded");
        return response;
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method getActivationListForUser");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The applicationId can be null, in this case all applications are used
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            logger.info("GetActivationListForUserRequest received, user ID: {}, application ID: {}", userId, applicationId);
            GetActivationListForUserResponse response = behavior.getActivationServiceBehavior().getActivationList(applicationId, userId);
            logger.info("GetActivationListForUserRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws GenericServiceException {
        if (request.getUserIds() == null || request.getUserIds().isEmpty()) {
            logger.warn("Invalid request parameter userIds in method lookupActivations");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            List<String> userIds = request.getUserIds();
            List<Long> applicationIds = request.getApplicationIds();
            Date timestampLastUsedBefore = null;
            if (request.getTimestampLastUsedBefore() != null) {
                timestampLastUsedBefore = XMLGregorianCalendarConverter.convertTo(request.getTimestampLastUsedBefore());
            }
            Date timestampLastUsedAfter = null;
            if (request.getTimestampLastUsedAfter() != null) {
                timestampLastUsedAfter = XMLGregorianCalendarConverter.convertTo(request.getTimestampLastUsedAfter());
            }
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusConverter.convert(request.getActivationStatus());
            }
            logger.info("LookupActivationsRequest received");
            LookupActivationsResponse response = behavior.getActivationServiceBehavior().lookupActivations(userIds, applicationIds, timestampLastUsedBefore, timestampLastUsedAfter, activationStatus);
            logger.info("LookupActivationsRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws GenericServiceException {
        if (request.getActivationIds() == null || request.getActivationIds().isEmpty()) {
            logger.warn("Invalid request parameter activationIds in method updateStatusForActivations");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            List<String> activationIds = request.getActivationIds();
            ActivationStatus activationStatus = null;
            if (request.getActivationStatus() != null) {
                activationStatus = activationStatusConverter.convert(request.getActivationStatus());
            }
            logger.info("UpdateStatusForActivationsRequest received");
            UpdateStatusForActivationsResponse response = behavior.getActivationServiceBehavior().updateStatusForActivation(activationIds, activationStatus);
            logger.info("UpdateStatusForActivationsRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method getActivationStatus");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String challenge = request.getChallenge();
            logger.info("GetActivationStatusRequest received, activation ID: {}", activationId);
            GetActivationStatusResponse response = behavior.getActivationServiceBehavior().getActivationStatus(activationId, challenge, keyConversionUtilities);
            logger.info("GetActivationStatusResponse succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public InitActivationResponse initActivation(InitActivationRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method initActivation");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The maxFailedCount and activationExpireTimestamp values can be null, in this case default values are used
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = XMLGregorianCalendarConverter.convertTo(request.getTimestampActivationExpire());
            logger.info("InitActivationRequest received, user ID: {}, application ID: {}", userId, applicationId);
            InitActivationResponse response = behavior.getActivationServiceBehavior().initActivation(applicationId, userId, maxFailedCount, activationExpireTimestamp, keyConversionUtilities);
            logger.info("InitActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws GenericServiceException {
        if (request.getActivationCode() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getMac() == null || request.getEncryptedData() == null) {
            logger.warn("Invalid request parameters in prepareActivation method");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationCode = request.getActivationCode();
            String applicationKey = request.getApplicationKey();
            byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            byte[] mac = BaseEncoding.base64().decode(request.getMac());
            byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;
            EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);
            logger.info("PrepareActivationRequest received, activation code: {}", activationCode);
            PrepareActivationResponse response = behavior.getActivationServiceBehavior().prepareActivation(activationCode, applicationKey, cryptogram, keyConversionUtilities);
            logger.info("PrepareActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws GenericServiceException {
        if (request.getUserId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getMac() == null || request.getEncryptedData() == null) {
            logger.warn("Invalid request parameters in createActivation method");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            // Get request parameters
            String userId = request.getUserId();
            Date activationExpireTimestamp = XMLGregorianCalendarConverter.convertTo(request.getTimestampActivationExpire());
            Long maxFailedCount = request.getMaxFailureCount();
            String applicationKey = request.getApplicationKey();
            byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            byte[] mac = BaseEncoding.base64().decode(request.getMac());
            byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;
            EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);
            logger.info("CreateActivationRequest received, user ID: {}", userId);
            CreateActivationResponse response = behavior.getActivationServiceBehavior().createActivation(
                    userId,
                    activationExpireTimestamp,
                    maxFailedCount,
                    applicationKey,
                    cryptogram,
                    keyConversionUtilities
            );
            logger.info("CreateActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    private VerifySignatureResponse verifySignatureImplNonTransaction(VerifySignatureRequest request, KeyValueMap additionalInfo) throws GenericServiceException {
        // Get request data
        String activationId = request.getActivationId();
        String applicationKey = request.getApplicationKey();
        String dataString = request.getData();
        String signature = request.getSignature();
        String signatureVersion = request.getSignatureVersion();
        SignatureType signatureType = request.getSignatureType();
        // Forced signature version during upgrade, currently only version 3 is supported
        Integer forcedSignatureVersion = null;
        if (request.getForcedSignatureVersion() != null && request.getForcedSignatureVersion() == 3) {
            forcedSignatureVersion = 3;
        }
        return behavior.getOnlineSignatureServiceBehavior().verifySignature(activationId, signatureType, signature, signatureVersion, additionalInfo, dataString, applicationKey, forcedSignatureVersion, keyConversionUtilities);
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getData() == null
                || request.getSignature() == null || request.getSignatureType() == null || request.getSignatureVersion() == null) {
            logger.warn("Invalid request parameters in method verifySignature");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("VerifySignatureRequest received, activation ID: {}", request.getActivationId());
            KeyValueMap additionalInfo = new KeyValueMap();
            VerifySignatureResponse response = this.verifySignatureImplNonTransaction(request, additionalInfo);
            logger.info("VerifySignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null) {
            logger.warn("Invalid request parameters in method createPersonalizedOfflineSignaturePayload");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String data = request.getData();
            logger.info("CreatePersonalizedOfflineSignaturePayloadRequest received, activation ID: {}", activationId);
            CreatePersonalizedOfflineSignaturePayloadResponse response = behavior.getOfflineSignatureServiceBehavior().createPersonalizedOfflineSignaturePayload(activationId, data, keyConversionUtilities);
            logger.info("CreatePersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws GenericServiceException {
        if (request.getData() == null) {
            logger.warn("Invalid request parameter data in method createNonPersonalizedOfflineSignaturePayload");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            long applicationId = request.getApplicationId();
            String data = request.getData();
            logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest received, application ID: {}", applicationId);
            CreateNonPersonalizedOfflineSignaturePayloadResponse response = behavior.getOfflineSignatureServiceBehavior().createNonPersonalizedOfflineSignaturePayload(applicationId, data, keyConversionUtilities);
            logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null || request.getSignature() == null) {
            logger.warn("Invalid request parameters in method verifyOfflineSignature");
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
            KeyValueMap additionalInfo = new KeyValueMap();
            logger.info("VerifyOfflineSignatureRequest received, activation ID: {}", activationId);
            VerifyOfflineSignatureResponse response = behavior.getOfflineSignatureServiceBehavior().verifyOfflineSignature(activationId, allowedSignatureTypes, signature, additionalInfo, data, keyConversionUtilities);
            logger.info("VerifyOfflineSignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method commitActivation");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String externalUserId = request.getExternalUserId();
            logger.info("CommitActivationRequest received, activation ID: {}", activationId);
            CommitActivationResponse response = behavior.getActivationServiceBehavior().commitActivation(activationId, externalUserId);
            logger.info("CommitActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method removeActivation");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String externalUserId = request.getExternalUserId();
            logger.info("RemoveActivationRequest received, activation ID: {}", activationId);
            RemoveActivationResponse response = behavior.getActivationServiceBehavior().removeActivation(activationId, externalUserId);
            logger.info("RemoveActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method blockActivation");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String reason = request.getReason();
            String externalUserId = request.getExternalUserId();
            logger.info("BlockActivationRequest received, activation ID: {}", activationId);
            BlockActivationResponse response = behavior.getActivationServiceBehavior().blockActivation(activationId, reason, externalUserId);
            logger.info("BlockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method unblockActivation");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String externalUserId = request.getExternalUserId();
            logger.info("UnblockActivationRequest received, activation ID: {}", activationId);
            UnblockActivationResponse response = behavior.getActivationServiceBehavior().unblockActivation(activationId, externalUserId);
            logger.info("UnblockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getSignature() == null
                || request.getSignatureType() == null || request.getSignatureVersion() == null || request.getSignedData() == null
                || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method vaultUnlock");
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
            byte[] ephemeralPublicKey = BaseEncoding.base64().decode(request.getEphemeralPublicKey());
            byte[] encryptedData = BaseEncoding.base64().decode(request.getEncryptedData());
            byte[] mac = BaseEncoding.base64().decode(request.getMac());
            byte[] nonce = request.getNonce() != null ? BaseEncoding.base64().decode(request.getNonce()) : null;

            logger.info("VaultUnlockRequest received, activation ID: {}", activationId);

            // The only allowed signature type is POSESSION_KNOWLEDGE to prevent attacks with weaker signature types
            if (!signatureType.equals(SignatureType.POSSESSION_KNOWLEDGE)) {
                // POSSESSION_BIOMETRY can also be used, but must be explicitly allowed in the configuration.
                if (!(signatureType.equals(SignatureType.POSSESSION_BIOMETRY) &&
                        powerAuthServiceConfiguration.isSecureVaultBiometricAuthenticationEnabled())) {
                    logger.warn("Invalid signature type: {}", signatureType);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
                }
            }

            // Convert received ECIES request data to cryptogram
            final EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData, nonce);

            VaultUnlockResponse response = behavior.getVaultUnlockServiceBehavior().unlockVault(activationId, applicationKey,
                    signature, signatureType, signatureVersion, signedData, cryptogram, keyConversionUtilities);
            logger.info("VaultUnlockRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getData() == null || request.getSignature() == null) {
            logger.warn("Invalid request parameters in method verifyECDSASignature");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            String signedData = request.getData();
            String signature  = request.getSignature();
            logger.info("VerifyECDSASignatureRequest received, activation ID: {}", activationId);
            boolean matches = behavior.getAsymmetricSignatureServiceBehavior().verifyECDSASignature(activationId, signedData, signature, keyConversionUtilities);
            VerifyECDSASignatureResponse response = new VerifyECDSASignatureResponse();
            response.setSignatureValid(matches);
            logger.info("VerifyECDSASignatureRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws GenericServiceException {
        if (request.getUserId() == null) {
            logger.warn("Invalid request parameter userId in method getSignatureAuditLog");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {

            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Date startingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampFrom());
            Date endingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampTo());

            logger.info("SignatureAuditRequest received, user ID: {}, application ID: {}", userId, applicationId);
            SignatureAuditResponse response = behavior.getAuditingServiceBehavior().getSignatureAuditLog(userId, applicationId, startingDate, endingDate);
            logger.info("SignatureAuditRequest succeeded");
            return response;

        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws GenericServiceException {
        if (request.getActivationId() == null) {
            logger.warn("Invalid request parameter activationId in method getActivationHistory");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            String activationId = request.getActivationId();
            Date startingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampFrom());
            Date endingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampTo());
            logger.info("ActivationHistoryRequest received, activation ID: {}", activationId);
            ActivationHistoryResponse response = behavior.getActivationHistoryServiceBehavior().getActivationHistory(activationId, startingDate, endingDate);
            logger.info("ActivationHistoryRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws GenericServiceException {
        try {
            logger.info("GetApplicationListRequest received");
            GetApplicationListResponse response = behavior.getApplicationServiceBehavior().getApplicationList();
            logger.info("GetApplicationListRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws GenericServiceException {
        try {
            GetApplicationDetailResponse response;
            if (request.getApplicationId() != null && request.getApplicationName() == null) {
                logger.info("GetApplicationDetailRequest received, application ID: {}", request.getApplicationId());
                response = behavior.getApplicationServiceBehavior().getApplicationDetail(request.getApplicationId());
            } else if (request.getApplicationName() != null && request.getApplicationId() == null) {
                logger.info("GetApplicationDetailRequest received, application name: '{}'", request.getApplicationName());
                response = behavior.getApplicationServiceBehavior().getApplicationDetailByName(request.getApplicationName());
            } else {
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            logger.info("GetApplicationDetailRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null) {
            logger.warn("Invalid request parameter applicationKey in method lookupApplicationByAppKey");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("LookupApplicationByAppKeyRequest received");
            LookupApplicationByAppKeyResponse response = behavior.getApplicationServiceBehavior().lookupApplicationByAppKey(request.getApplicationKey());
            logger.info("LookupApplicationByAppKeyRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws GenericServiceException {
        if (request.getApplicationName() == null) {
            logger.warn("Invalid request parameter applicationName in method createApplication");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateApplicationRequest received, application name: {}", request.getApplicationName());
            CreateApplicationResponse response = behavior.getApplicationServiceBehavior().createApplication(request.getApplicationName(), keyConversionUtilities);
            logger.info("CreateApplicationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws GenericServiceException {
        if (request.getApplicationVersionName() == null) {
            logger.warn("Invalid request parameter applicationVersionName in method createApplicationVersion");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateApplicationVersionRequest received, application ID: {}, application version name: {}", request.getApplicationId(), request.getApplicationVersionName());
            CreateApplicationVersionResponse response = behavior.getApplicationServiceBehavior().createApplicationVersion(request.getApplicationId(), request.getApplicationVersionName());
            logger.info("CreateApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("UnsupportApplicationVersionRequest received, application version ID: {}", request.getApplicationVersionId());
            UnsupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().unsupportApplicationVersion(request.getApplicationVersionId());
            logger.info("UnsupportApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws GenericServiceException {
        try {
            logger.info("SupportApplicationVersionRequest received, application version ID: {}", request.getApplicationVersionId());
            SupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().supportApplicationVersion(request.getApplicationVersionId());
            logger.info("SupportApplicationVersionRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws GenericServiceException {
        if (request.getName() == null) {
            logger.warn("Invalid request parameter name in method createIntegration");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateIntegrationRequest received, name: {}", request.getName());
            CreateIntegrationResponse response = behavior.getIntegrationBehavior().createIntegration(request);
            logger.info("CreateIntegrationRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetIntegrationListResponse getIntegrationList() throws GenericServiceException {
        try {
            logger.info("GetIntegrationListRequest received");
            GetIntegrationListResponse response = behavior.getIntegrationBehavior().getIntegrationList();
            logger.info("GetIntegrationListRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws GenericServiceException {
        try {
            logger.info("RemoveIntegrationRequest received, id: {}", request.getId());
            RemoveIntegrationResponse response = behavior.getIntegrationBehavior().removeIntegration(request);
            logger.info("RemoveIntegrationRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws GenericServiceException {
        if (request.getName() == null) {
            logger.warn("Invalid request parameter name in method createCallbackUrl");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateCallbackUrlRequest received, name: {}", request.getName());
            CreateCallbackUrlResponse response = behavior.getCallbackUrlBehavior().createCallbackUrl(request);
            logger.info("CreateCallbackUrlRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws GenericServiceException {
        try {
            logger.info("GetCallbackUrlListRequest received, application ID: {}", request.getApplicationId());
            GetCallbackUrlListResponse response = behavior.getCallbackUrlBehavior().getCallbackUrlList(request);
            logger.info("GetCallbackUrlListRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws GenericServiceException {
        try {
            logger.info("RemoveCallbackUrlRequest received, id: {}", request.getId());
            RemoveCallbackUrlResponse response = behavior.getCallbackUrlBehavior().removeCallbackUrl(request);
            logger.info("RemoveCallbackUrlRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateTokenResponse createToken(CreateTokenRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method createToken");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateTokenRequest received, activation ID: {}", request.getActivationId());
            CreateTokenResponse response = behavior.getTokenBehavior().createToken(request, keyConversionUtilities);
            logger.info("CreateTokenRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws GenericServiceException {
        if (request.getTokenId() == null || request.getNonce() == null || request.getTokenDigest() == null) {
            logger.warn("Invalid request parameters in method validateToken");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // Verify the token timestamp validity
        if (request.getTimestamp() < System.currentTimeMillis() - powerAuthServiceConfiguration.getTokenTimestampValidityInMilliseconds()) {
            logger.warn("Invalid request - token timestamp is too old for token ID: {}", request.getTokenId());
            throw localizationProvider.buildExceptionForCode(ServiceError.TOKEN_TIMESTAMP_TOO_OLD);
        }
        try {
            logger.info("ValidateTokenRequest received, token ID: {}", request.getTokenId());
            ValidateTokenResponse response = behavior.getTokenBehavior().validateToken(request);
            logger.info("ValidateTokenRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws GenericServiceException {
        if (request.getTokenId() == null) {
            logger.warn("Invalid request parameter tokenId in method removeToken");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RemoveTokenRequest received, token ID: {}", request.getTokenId());
            RemoveTokenResponse response = behavior.getTokenBehavior().removeToken(request);
            logger.info("RemoveTokenRequest succeeded");
            return response;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws GenericServiceException {
        if (request.getApplicationKey() == null || request.getEphemeralPublicKey() == null) {
            logger.warn("Invalid request parameters in method getEciesDecryptor");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        // The activationId value can be null in case the decryptor is used in application scope
        try {
            logger.info("GetEciesDecryptorRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            GetEciesDecryptorResponse response = behavior.getEciesEncryptionBehavior().getEciesDecryptorParameters(request);
            logger.info("GetEciesDecryptorRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method startUpgrade");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("StartUpgradeRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            StartUpgradeResponse response = behavior.getUpgradeServiceBehavior().startUpgrade(request);
            logger.info("StartUpgradeRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null) {
            logger.warn("Invalid request parameters in method commitUpgrade");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CommitUpgradeRequest received, application key: {}, activation ID: {}", request.getApplicationKey(), request.getActivationId());
            CommitUpgradeResponse response = behavior.getUpgradeServiceBehavior().commitUpgrade(request);
            logger.info("CommitUpgradeRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L || request.getUserId() == null || request.getPukCount() < 1 || request.getPukCount() > RecoveryServiceBehavior.PUK_COUNT_MAX) {
            logger.warn("Invalid request parameters in method createRecoveryCode");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("CreateRecoveryCodeRequest received, application ID: {}, user ID: {}", request.getApplicationId(), request.getUserId());
            CreateRecoveryCodeResponse response = behavior.getRecoveryServiceBehavior().createRecoveryCode(request, keyConversionUtilities);
            logger.info("CreateRecoveryCodeRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws GenericServiceException {
        if (request.getActivationId() == null || request.getApplicationKey() == null || request.getEphemeralPublicKey() == null
                || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method confirmRecoveryCode");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("ConfirmRecoveryCodeRequest received, activation ID: {}, application key: {}", request.getActivationId(), request.getApplicationKey());
            ConfirmRecoveryCodeResponse response = behavior.getRecoveryServiceBehavior().confirmRecoveryCode(request, keyConversionUtilities);
            logger.info("ConfirmRecoveryCodeRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws GenericServiceException {
        if (request.getApplicationId() == null && request.getUserId() == null && request.getActivationId() == null) {
            logger.warn("Invalid request parameters in method lookupRecoveryCodes");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("LookupRecoveryCodesRequest received, application ID: {}, user ID: {}, activation ID: {}", request.getApplicationId(), request.getUserId(), request.getActivationId());
            LookupRecoveryCodesResponse response = behavior.getRecoveryServiceBehavior().lookupRecoveryCodes(request);
            logger.info("LookupRecoveryCodesRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws GenericServiceException {
        if (request.getRecoveryCodeIds() == null || request.getRecoveryCodeIds().isEmpty()) {
            logger.warn("Invalid request parameters in method revokeRecoveryCodes");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RevokeRecoveryCodesRequest received, recovery code IDs: {}", request.getRecoveryCodeIds());
            RevokeRecoveryCodesResponse response = behavior.getRecoveryServiceBehavior().revokeRecoveryCodes(request);
            logger.info("RevokeRecoveryCodesRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws GenericServiceException {
        if (request.getRecoveryCode() == null || request.getPuk() == null || request.getApplicationKey() == null
            || request.getEphemeralPublicKey() == null || request.getEncryptedData() == null || request.getMac() == null) {
            logger.warn("Invalid request parameters in method createActivationUsingRecoveryCode");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("RecoveryCodeActivationRequest received, recovery code: {}, application key: {}", request.getRecoveryCode(), request.getApplicationKey());
            RecoveryCodeActivationResponse response = behavior.getActivationServiceBehavior().createActivationUsingRecoveryCode(request, keyConversionUtilities);
            logger.info("RecoveryCodeActivationRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method getRecoveryConfig");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("GetRecoveryConfigRequest received, application ID: {}", request.getApplicationId());
            GetRecoveryConfigResponse response = behavior.getRecoveryServiceBehavior().getRecoveryConfig(request);
            logger.info("GetRecoveryConfigRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional(rollbackFor = GenericServiceException.class)
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws GenericServiceException {
        if (request.getApplicationId() <= 0L) {
            logger.warn("Invalid request parameter applicationId in method updateRecoveryConfig");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        try {
            logger.info("GetRecoveryConfigRequest received, application ID: {}", request.getApplicationId());
            UpdateRecoveryConfigResponse response = behavior.getRecoveryServiceBehavior().updateRecoveryConfig(request, keyConversionUtilities);
            logger.info("GetRecoveryConfigRequest succeeeded");
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

}
