/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.*;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.XMLGregorianCalendarConverter;
import io.getlime.security.powerauth.app.server.database.model.AdditionalInformation;
import io.getlime.security.powerauth.app.server.service.behavior.ServiceBehaviorCatalogue;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default implementation of the PowerAuth 2.0 Server service.
 * The implementation of this service is divided into "behaviors"
 * responsible for individual processes.
 *
 * @see io.getlime.security.powerauth.app.server.service.PowerAuthService
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class PowerAuthServiceImpl implements PowerAuthService {

    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    private ServiceBehaviorCatalogue behavior;

    private LocalizationProvider localizationProvider;

    private BuildProperties buildProperties;

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
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetSystemStatusRequest received");
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
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetSystemStatusRequest succeeded");
        return response;
    }

    @Override
    public GetErrorCodeListResponse getErrorCodeList(GetErrorCodeListRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetErrorCodeListRequest received");
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
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetErrorCodeListRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws Exception {
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetActivationListForUserRequest received, userId: {0}, applicationId: {1}", new String[] {userId, String.valueOf(applicationId)});
            GetActivationListForUserResponse response = behavior.getActivationServiceBehavior().getActivationList(applicationId, userId);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetActivationListForUserRequest succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetActivationStatusRequest received, activationId: {0}", activationId);
            GetActivationStatusResponse response = behavior.getActivationServiceBehavior().getActivationStatus(activationId, keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetActivationStatusResponse succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional
    public InitActivationResponse initActivation(InitActivationRequest request) throws Exception {
        try {
            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = XMLGregorianCalendarConverter.convertTo(request.getTimestampActivationExpire());
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "InitActivationRequest received, userId: {0}, applicationId: {1}", new String[] {userId, String.valueOf(applicationId)});
            InitActivationResponse response = behavior.getActivationServiceBehavior().initActivation(applicationId, userId, maxFailedCount, activationExpireTimestamp, keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "InitActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_KEY_FORMAT);
        }
    }

    @Override
    @Transactional
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws Exception {
        try {
            // Get request parameters
            String activationIdShort = request.getActivationIdShort();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationKey = request.getApplicationKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "PrepareActivationRequest received, activationIdShort: {0}", activationIdShort);
            PrepareActivationResponse response = behavior.getActivationServiceBehavior().prepareActivation(activationIdShort, activationNonceBase64, ephemeralPublicKey, cDevicePublicKeyBase64, activationName, extras, applicationKey, applicationSignature, keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "PrepareActivationRequest succeeded");
            return response;
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws Exception {
        try {
            // Get request parameters
            String applicationKey = request.getApplicationKey();
            String userId = request.getUserId();
            Long maxFailedCount = request.getMaxFailureCount();
            Date activationExpireTimestamp = XMLGregorianCalendarConverter.convertTo(request.getTimestampActivationExpire());
            String identity = request.getIdentity();
            String activationOtp = request.getActivationOtp();
            String activationNonceBase64 = request.getActivationNonce();
            String cDevicePublicKeyBase64 = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String ephemeralPublicKey = request.getEphemeralPublicKey();
            String applicationSignature = request.getApplicationSignature();
            String extras = request.getExtras();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateActivationRequest received, userId: {0}", userId);
            CreateActivationResponse response = behavior.getActivationServiceBehavior().createActivation(
                    applicationKey,
                    userId,
                    maxFailedCount,
                    activationExpireTimestamp,
                    identity,
                    activationOtp,
                    activationNonceBase64,
                    ephemeralPublicKey,
                    cDevicePublicKeyBase64,
                    activationName,
                    extras,
                    applicationSignature,
                    keyConversionUtilities
            );
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateActivationRequest succeeded");
            return response;
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    private VerifySignatureResponse verifySignatureImplNonTransaction(VerifySignatureRequest request, KeyValueMap additionalInfo) throws Exception {

        // Get request data
        String activationId = request.getActivationId();
        String applicationKey = request.getApplicationKey();
        String dataString = request.getData();
        String signature = request.getSignature();
        SignatureType signatureType = request.getSignatureType();

        return behavior.getSignatureServiceBehavior().verifySignature(activationId, signatureType, signature, additionalInfo, dataString, applicationKey, keyConversionUtilities);

    }

    @Override
    @Transactional
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws Exception {
        try {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifySignatureRequest received, activationId: {0}", request.getActivationId());
            VerifySignatureResponse response = this.verifySignatureImplNonTransaction(request, null);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifySignatureRequest succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            String data = request.getData();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreatePersonalizedOfflineSignaturePayloadRequest received, activationId: {0}", activationId);
            CreatePersonalizedOfflineSignaturePayloadResponse response = behavior.getSignatureServiceBehavior().createPersonalizedOfflineSignaturePayload(activationId, data, keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreatePersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw new GenericServiceException(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws Exception {
        try {
            long applicationId = request.getApplicationId();
            String data = request.getData();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateNonPersonalizedOfflineSignaturePayloadRequest received, applicationId: {0}", String.valueOf(applicationId));
            CreateNonPersonalizedOfflineSignaturePayloadResponse response = behavior.getSignatureServiceBehavior().createNonPersonalizedOfflineSignaturePayload(applicationId, data, keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateNonPersonalizedOfflineSignaturePayloadRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            throw new GenericServiceException(ServiceError.UNABLE_TO_COMPUTE_SIGNATURE, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws Exception {
        final String activationId = request.getActivationId();
        final String data = request.getData();
        final String signature = request.getSignature();
        final SignatureType signatureType = request.getSignatureType();
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifyOfflineSignatureRequest received, activationId: {0}", activationId);
        VerifyOfflineSignatureResponse response = behavior.getSignatureServiceBehavior().verifyOfflineSignature(activationId, signatureType, signature, data, keyConversionUtilities);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifyOfflineSignatureRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CommitActivationRequest received, activationId: {0}", activationId);
            CommitActivationResponse response = behavior.getActivationServiceBehavior().commitActivation(activationId);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CommitActivationRequest succeeded", request.getActivationId());
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveActivationRequest received, activationId: {0}", activationId);
            RemoveActivationResponse response = behavior.getActivationServiceBehavior().removeActivation(activationId);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveActivationRequest succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            String reason = request.getReason();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "BlockActivationRequest received, activationId: {0}", activationId);
            BlockActivationResponse response = behavior.getActivationServiceBehavior().blockActivation(activationId, reason);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "BlockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "UnblockActivationRequest received, activationId: {0}", activationId);
            UnblockActivationResponse response = behavior.getActivationServiceBehavior().unblockActivation(activationId);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "UnblockActivationRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    @Transactional
    public VaultUnlockResponse vaultUnlock(VaultUnlockRequest request) throws Exception {
        try {

            // Get request data
            String activationId = request.getActivationId();
            String applicationKey = request.getApplicationKey();
            String signature = request.getSignature();
            SignatureType signatureType = request.getSignatureType();
            String data = request.getData();
            String reason = request.getReason();

            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VaultUnlockRequest received, activationId: {0}", activationId);

            // Reject 1FA signatures.
            if (signatureType.equals(SignatureType.BIOMETRY)
                    || signatureType.equals(SignatureType.KNOWLEDGE)
                    || signatureType.equals(SignatureType.POSSESSION)) {
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_SIGNATURE);
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
            VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
            verifySignatureRequest.setActivationId(activationId);
            verifySignatureRequest.setApplicationKey(applicationKey);
            verifySignatureRequest.setData(data);
            verifySignatureRequest.setSignature(signature);
            verifySignatureRequest.setSignatureType(signatureType);
            VerifySignatureResponse verifySignatureResponse = this.verifySignatureImplNonTransaction(verifySignatureRequest, additionalInfo);

            VaultUnlockResponse response = behavior.getVaultUnlockServiceBehavior().unlockVault(activationId, verifySignatureResponse.isSignatureValid(), keyConversionUtilities);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VaultUnlockRequest succeeded");
            return response;
        } catch (GenericServiceException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetPersonalizedEncryptionKeyResponse generateE2EPersonalizedEncryptionKey(GetPersonalizedEncryptionKeyRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetPersonalizedEncryptionKeyRequest received, activationId: {0}", request.getActivationId());
        GetPersonalizedEncryptionKeyResponse response = behavior.getEncryptionServiceBehavior().generateEncryptionKeyForActivation(
                request.getActivationId(),
                request.getSessionIndex(),
                keyConversionUtilities
        );
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetPersonalizedEncryptionKeyRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetNonPersonalizedEncryptionKeyResponse generateE2ENonPersonalizedEncryptionKey(GetNonPersonalizedEncryptionKeyRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetNonPersonalizedEncryptionKeyRequest received");
        GetNonPersonalizedEncryptionKeyResponse response = behavior.getEncryptionServiceBehavior().generateNonPersonalizedEncryptionKeyForApplication(
                request.getApplicationKey(),
                request.getSessionIndex(),
                request.getEphemeralPublicKey(),
                keyConversionUtilities
        );
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetNonPersonalizedEncryptionKeyRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            String signedData = request.getData();
            String signature  = request.getSignature();
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifyECDSASignatureRequest received, activationId: {0}", activationId);
            boolean matches = behavior.getAsymmetricSignatureServiceBehavior().verifyECDSASignature(activationId, signedData, signature, keyConversionUtilities);
            VerifyECDSASignatureResponse response = new VerifyECDSASignatureResponse();
            response.setSignatureValid(matches);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "VerifyECDSASignatureRequest succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws Exception {
        try {

            String userId = request.getUserId();
            Long applicationId = request.getApplicationId();
            Date startingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampFrom());
            Date endingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampTo());

            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "SignatureAuditRequest received, userId: {0}, applicationId: {1}", new String[]{userId, String.valueOf(applicationId)});
            SignatureAuditResponse response = behavior.getAuditingServiceBehavior().getSignatureAuditLog(userId, applicationId, startingDate, endingDate);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "SignatureAuditRequest succeeded");
            return response;

        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }

    }

    @Override
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws Exception {
        try {
            String activationId = request.getActivationId();
            Date startingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampFrom());
            Date endingDate = XMLGregorianCalendarConverter.convertTo(request.getTimestampTo());
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "ActivationHistoryRequest received, activationId: {0}", activationId);
            ActivationHistoryResponse response = behavior.getActivationHistoryServiceBehavior().getActivationHistory(activationId, startingDate, endingDate);
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "ActivationHistoryRequest succeeded");
            return response;
        } catch (Exception ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    @Override
    @Transactional
    public GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetApplicationListRequest received");
        GetApplicationListResponse response = behavior.getApplicationServiceBehavior().getApplicationList();
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetApplicationListRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetApplicationDetailRequest received, applicationId: {0}", String.valueOf(request.getApplicationId()));
        GetApplicationDetailResponse response = behavior.getApplicationServiceBehavior().getApplicationDetail(request.getApplicationId());
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetApplicationDetailRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws Exception {
        try {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "LookupApplicationByAppKeyRequest received");
            LookupApplicationByAppKeyResponse response = behavior.getApplicationServiceBehavior().lookupApplicationByAppKey(request.getApplicationKey());
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "LookupApplicationByAppKeyRequest succeeded");
            return response;
        } catch (Throwable t) {
            throw localizationProvider.buildExceptionForCode(ServiceError.NO_APPLICATION_ID);
        }
    }

    @Override
    @Transactional
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateApplicationRequest received, applicationName: {0}", request.getApplicationName());
        CreateApplicationResponse response = behavior.getApplicationServiceBehavior().createApplication(request.getApplicationName(), keyConversionUtilities);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateApplicationRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateApplicationVersionRequest received, applicationId: {0}, applicationVersionName: {1}", new String[]{String.valueOf(request.getApplicationId()), request.getApplicationVersionName()});
        CreateApplicationVersionResponse response = behavior.getApplicationServiceBehavior().createApplicationVersion(request.getApplicationId(), request.getApplicationVersionName());
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateApplicationVersionRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "UnsupportApplicationVersionRequest received, applicationVersionId: {0}", request.getApplicationVersionId());
        UnsupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().unsupportApplicationVersion(request.getApplicationVersionId());
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "UnsupportApplicationVersionRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "SupportApplicationVersionRequest received, applicationVersionId: {0}", request.getApplicationVersionId());
        SupportApplicationVersionResponse response = behavior.getApplicationServiceBehavior().supportApplicationVersion(request.getApplicationVersionId());
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "SupportApplicationVersionRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateIntegrationRequest received, name: {0}", request.getName());
        CreateIntegrationResponse response = behavior.getIntegrationBehavior().createIntegration(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateIntegrationRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetIntegrationListResponse getIntegrationList() throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetIntegrationListRequest received");
        GetIntegrationListResponse response = behavior.getIntegrationBehavior().getIntegrationList();
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetIntegrationListRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveIntegrationRequest received, id: {0}", request.getId());
        RemoveIntegrationResponse response = behavior.getIntegrationBehavior().removeIntegration(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveIntegrationRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateCallbackUrlRequest received, name: {0}", request.getName());
        CreateCallbackUrlResponse response = behavior.getCallbackUrlBehavior().createCallbackUrl(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateCallbackUrlRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetCallbackUrlListRequest received, applicationId: {0}", String.valueOf(request.getApplicationId()));
        GetCallbackUrlListResponse response = behavior.getCallbackUrlBehavior().getCallbackUrlList(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "GetCallbackUrlListRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveCallbackUrlRequest received, id: {0}", request.getId());
        RemoveCallbackUrlResponse response = behavior.getCallbackUrlBehavior().removeIntegration(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveCallbackUrlRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public CreateTokenResponse createToken(CreateTokenRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateTokenRequest received, activationId: {0}", request.getActivationId());
        CreateTokenResponse response = behavior.getTokenBehavior().createToken(request, keyConversionUtilities);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "CreateTokenRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "ValidateTokenRequest received, tokenId: {0}", request.getTokenId());
        ValidateTokenResponse response = behavior.getTokenBehavior().validateToken(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "ValidateTokenRequest succeeded");
        return response;
    }

    @Override
    @Transactional
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws Exception {
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveTokenRequest received, tokenId: {0}", request.getTokenId());
        RemoveTokenResponse response = behavior.getTokenBehavior().removeToken(request);
        Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.INFO, "RemoveTokenRequest succeeded");
        return response;
    }

}
