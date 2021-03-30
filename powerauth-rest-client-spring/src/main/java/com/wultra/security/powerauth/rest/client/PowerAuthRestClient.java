/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.*;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.ActivationHistoryRequest;
import com.wultra.security.powerauth.client.model.request.AddActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.AddApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.BlockActivationRequest;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.ConfirmRecoveryCodeRequest;
import com.wultra.security.powerauth.client.model.request.CreateActivationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationRequest;
import com.wultra.security.powerauth.client.model.request.CreateApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.CreateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.CreateIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.CreateNonPersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.CreateRecoveryCodeRequest;
import com.wultra.security.powerauth.client.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.GetActivationListForUserRequest;
import com.wultra.security.powerauth.client.model.request.GetActivationStatusRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationDetailRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationListRequest;
import com.wultra.security.powerauth.client.model.request.GetCallbackUrlListRequest;
import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.request.GetErrorCodeListRequest;
import com.wultra.security.powerauth.client.model.request.GetIntegrationListRequest;
import com.wultra.security.powerauth.client.model.request.GetRecoveryConfigRequest;
import com.wultra.security.powerauth.client.model.request.GetSystemStatusRequest;
import com.wultra.security.powerauth.client.model.request.InitActivationRequest;
import com.wultra.security.powerauth.client.model.request.ListActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.ListApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.LookupActivationsRequest;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.request.LookupRecoveryCodesRequest;
import com.wultra.security.powerauth.client.model.request.PrepareActivationRequest;
import com.wultra.security.powerauth.client.model.request.RecoveryCodeActivationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.RemoveCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.RemoveIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.RevokeRecoveryCodesRequest;
import com.wultra.security.powerauth.client.model.request.SignatureAuditRequest;
import com.wultra.security.powerauth.client.model.request.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.SupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.UnblockActivationRequest;
import com.wultra.security.powerauth.client.model.request.UnsupportApplicationVersionRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationOtpRequest;
import com.wultra.security.powerauth.client.model.request.UpdateApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.UpdateCallbackUrlRequest;
import com.wultra.security.powerauth.client.model.request.UpdateRecoveryConfigRequest;
import com.wultra.security.powerauth.client.model.request.UpdateStatusForActivationsRequest;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.request.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.request.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.request.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.GetIntegrationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import javax.xml.datatype.XMLGregorianCalendar;
import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Class implementing a PowerAuth REST client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthRestClient implements PowerAuthClient {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthRestClient.class);

    private static final String PA_REST_V3_PREFIX = "/v3";

    private final RestClient restClient;
    private final ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl BASE URL of REST endpoints.
     */
    public PowerAuthRestClient(String baseUrl) throws PowerAuthClientException {
        this(baseUrl, new PowerAuthRestClientConfiguration());
    }

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl Base URL of REST endpoints.
     */
    public PowerAuthRestClient(String baseUrl, PowerAuthRestClientConfiguration config) throws PowerAuthClientException {
        DefaultRestClient.Builder builder = DefaultRestClient.builder().baseUrl(baseUrl)
                .acceptInvalidCertificate(config.getAcceptInvalidSslCertificate())
                .connectionTimeout(config.getConnectTimeout())
                .maxInMemorySize(config.getMaxMemorySize());
        if (config.isProxyEnabled()) {
            DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(config.getProxyHost()).port(config.getProxyPort());
            if (config.getProxyUsername() != null) {
                proxyBuilder.username(config.getProxyUsername()).password(config.getProxyPassword());
            }
            proxyBuilder.build();
        }
        if (config.getPowerAuthClientToken() != null) {
            builder.httpBasicAuth().username(config.getPowerAuthClientToken()).password(config.getPowerAuthClientSecret()).build();
        }
        try {
            restClient = builder.build();
        } catch (RestClientException ex) {
            throw new PowerAuthClientException("REST client initialization failed, error: " + ex.getMessage(), ex);
        }
    }

    /**
     * Call the PowerAuth v3 API.
     *
     * @param path Path of the endpoint.
     * @param request Request object.
     * @param responseType Response type.
     * @return Response.
     */
    private <T> T callV3RestApi(String path, Object request, Class<T> responseType) throws PowerAuthClientException {
        ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
        try {
            ObjectResponse<T> objectResponse = restClient.postObject(PA_REST_V3_PREFIX + path, objectRequest, responseType);
            return objectResponse.getResponseObject();
        } catch (RestClientException ex) {
            if (ex.getStatusCode() == HttpStatus.BAD_REQUEST) {
                // Error handling for PowerAuth errors
                handleBadRequestError(ex);
            }
            // Error handling for generic HTTP errors
            throw new PowerAuthClientException(ex.getMessage(), ex);
        }
    }

    /**
     * Handle the HTTP response with BAD_REQUEST status code.
     * @param ex Exception which captured the error.
     * @throws PowerAuthClientException PowerAuth client exception.
     */
    private void handleBadRequestError(RestClientException ex) throws PowerAuthClientException {
        // Try to parse exception into PowerAuthError model class
        try {
            TypeReference<ObjectResponse<PowerAuthError>> typeReference = new TypeReference<ObjectResponse<PowerAuthError>>(){};
            ObjectResponse<PowerAuthError> error = objectMapper.readValue(ex.getResponse(), typeReference);
            if (error == null || error.getResponseObject() == null) {
                throw new PowerAuthClientException("Invalid response object");
            }
            if ("ERR_RECOVERY".equals(error.getResponseObject().getCode())) {
                // In case of special recovery errors, return PowerAuthErrorRecovery which includes additional information about recovery
                TypeReference<ObjectResponse<PowerAuthErrorRecovery>> PowerAuthErrorRecovery = new TypeReference<ObjectResponse<PowerAuthErrorRecovery>>(){};
                ObjectResponse<PowerAuthErrorRecovery> errorRecovery = objectMapper.readValue(ex.getResponse(), PowerAuthErrorRecovery);
                if (errorRecovery == null || errorRecovery.getResponseObject() == null) {
                    throw new PowerAuthClientException("Invalid response object for recovery");
                }
                throw new PowerAuthClientException(errorRecovery.getResponseObject().getMessage(), ex, errorRecovery.getResponseObject());
            }
            throw new PowerAuthClientException(error.getResponseObject().getMessage(), ex, error.getResponseObject());
        } catch (IOException ex2) {
            // Parsing failed, return a regular error
            throw new PowerAuthClientException(ex.getMessage(), ex);
        }
    }

    /**
     * Convert date to XMLGregorianCalendar
     *
     * @param date Date to be converted.
     * @return A new instance of {@link XMLGregorianCalendar}.
     */
    private Instant instantWithDate(Date date) {
        return Instant.ofEpochMilli(date.getTime());
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse getSystemStatus(GetSystemStatusRequest request) throws PowerAuthClientException {
        return callV3RestApi("/status", request, com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException {
        GetSystemStatusRequest request = new GetSystemStatusRequest();
        return getSystemStatus(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException {
        return callV3RestApi("/error/list", request, com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException {
        GetErrorCodeListRequest request = new GetErrorCodeListRequest();
        request.setLanguage(language);
        return getErrorList(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/init", request, com.wultra.security.powerauth.client.model.response.InitActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, null, null, com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE, null);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, null, null, otpValidation, otp);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException {
        return this.initActivation(userId, applicationId, maxFailureCount, timestampActivationExpire, com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation.NONE, null);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.InitActivationResponse initActivation(String userId, Long applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                                                                                     com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
        InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setActivationOtpValidation(otpValidation);
        request.setActivationOtp(otp);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(instantWithDate(timestampActivationExpire));
        }
        return this.initActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/prepare", request, com.wultra.security.powerauth.client.model.response.PrepareActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
        PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return prepareActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/create", request, com.wultra.security.powerauth.client.model.response.CreateActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                                                                         String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                                                                         String mac, String nonce) throws PowerAuthClientException {
        CreateActivationRequest request = new CreateActivationRequest();
        request.setUserId(userId);
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(instantWithDate(timestampActivationExpire));
        }
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return createActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        UpdateActivationOtpRequest request = new UpdateActivationOtpRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return updateActivationOtp(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/otp/update", request, com.wultra.security.powerauth.client.model.response.UpdateActivationOtpResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/commit", request, com.wultra.security.powerauth.client.model.response.CommitActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.commitActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return this.commitActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/status", request, com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException {
        com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse response = this.getActivationStatusWithEncryptedStatusBlob(activationId, null);
        response.setEncryptedStatusBlob(null);
        return response;
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) throws PowerAuthClientException {
        GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return this.getActivationStatus(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/remove", request, com.wultra.security.powerauth.client.model.response.RemoveActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        return this.removeActivation(activationId, externalUserId, false);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveActivationResponse removeActivation(String activationId, String externalUserId, Boolean revokeRecoveryCodes) throws PowerAuthClientException {
        RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        return this.removeActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/list", request, com.wultra.security.powerauth.client.model.response.GetActivationListForUserResponse.class);
    }

    @Override
    public List<Activation> getActivationListForUser(String userId) throws PowerAuthClientException {
        GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return this.getActivationListForUser(request).getActivations();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/lookup", request, com.wultra.security.powerauth.client.model.response.LookupActivationsResponse.class);
    }

    @Override
    public List<Activation> lookupActivations(List<String> userIds, List<Long> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException {
        LookupActivationsRequest request = new LookupActivationsRequest();
        request.getUserIds().addAll(userIds);
        if (applicationIds != null) {
            request.getApplicationIds().addAll(applicationIds);
        }
        if (timestampLastUsedBefore != null) {
            request.setTimestampLastUsedBefore(instantWithDate(timestampLastUsedBefore));
        }
        if (timestampLastUsedAfter != null) {
            request.setTimestampLastUsedAfter(instantWithDate(timestampLastUsedAfter));
        }
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        if (activationFlags != null) {
            request.getActivationFlags().addAll(activationFlags);
        }
        return this.lookupActivations(request).getActivations();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/status/update", request, com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException {
        UpdateStatusForActivationsRequest request = new UpdateStatusForActivationsRequest();
        request.getActivationIds().addAll(activationIds);
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        return this.updateStatusForActivations(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/verify", request, com.wultra.security.powerauth.client.model.response.VerifySignatureResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) throws PowerAuthClientException {
        VerifySignatureRequest request = new VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setSignatureVersion(signatureVersion);
        request.setForcedSignatureVersion(forcedSignatureVersion);
        return this.verifySignature(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/personalized/create", request, com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws PowerAuthClientException {
        CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/non-personalized/create", request, com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(long applicationId, String data) throws PowerAuthClientException {
        CreateNonPersonalizedOfflineSignaturePayloadRequest request = new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/verify", request, com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) throws PowerAuthClientException {
        VerifyOfflineSignatureRequest request = new VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineSignature(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException {
        return callV3RestApi("/vault/unlock", request, com.wultra.security.powerauth.client.model.response.VaultUnlockResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                                                                               SignatureType signatureType, String signatureVersion, String signedData,
                                                                                               String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
        VaultUnlockRequest request = new VaultUnlockRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setSignedData(signedData);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setSignatureVersion(signatureVersion);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return unlockVault(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/ecdsa/verify", request, com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws PowerAuthClientException {
        VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return this.verifyECDSASignature(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException {
        return callV3RestApi("/signature/list", request, com.wultra.security.powerauth.client.model.response.SignatureAuditResponse.class);
    }

    @Override
    public List<SignatureAuditItem> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(instantWithDate(startingDate));
        request.setTimestampTo(instantWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public List<SignatureAuditItem> getSignatureAuditLog(String userId, Long applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(instantWithDate(startingDate));
        request.setTimestampTo(instantWithDate(endingDate));
        return this.getSignatureAuditLog(request).getItems();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/history", request, com.wultra.security.powerauth.client.model.response.ActivationHistoryResponse.class);
    }

    @Override
    public List<ActivationHistoryItem> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        ActivationHistoryRequest request = new ActivationHistoryRequest();
        request.setActivationId(activationId);
        request.setTimestampFrom(instantWithDate(startingDate));
        request.setTimestampTo(instantWithDate(endingDate));
        return this.getActivationHistory(request).getItems();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/block", request, com.wultra.security.powerauth.client.model.response.BlockActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException {
        BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        request.setExternalUserId(externalUserId);
        return this.blockActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/unblock", request, com.wultra.security.powerauth.client.model.response.UnblockActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return this.unblockActivation(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetApplicationListResponse getApplicationList(GetApplicationListRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/list", request, com.wultra.security.powerauth.client.model.response.GetApplicationListResponse.class);
    }

    @Override
    public List<Application> getApplicationList() throws PowerAuthClientException {
        return this.getApplicationList(new GetApplicationListRequest()).getApplications();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/detail", request, com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(Long applicationId) throws PowerAuthClientException {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return this.getApplicationDetail(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetApplicationDetailResponse getApplicationDetail(String applicationName) throws PowerAuthClientException {
        GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationName(applicationName);
        return this.getApplicationDetail(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/detail/version", request, com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) throws PowerAuthClientException {
        LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);
        return this.lookupApplicationByAppKey(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateApplicationResponse createApplication(CreateApplicationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/create", request, com.wultra.security.powerauth.client.model.response.CreateApplicationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateApplicationResponse createApplication(String name) throws PowerAuthClientException {
        CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationName(name);
        return this.createApplication(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/version/create", request, com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) throws PowerAuthClientException {
        CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionName(versionName);
        return this.createApplicationVersion(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/version/unsupport", request, com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) throws PowerAuthClientException {
        UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.unsupportApplicationVersion(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/version/support", request, com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.SupportApplicationVersionResponse supportApplicationVersion(Long versionId) throws PowerAuthClientException {
        SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationVersionId(versionId);
        return this.supportApplicationVersion(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/integration/create", request, com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException {
        CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return this.createIntegration(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetIntegrationListResponse getIntegrationList(GetIntegrationListRequest request) throws PowerAuthClientException {
        return callV3RestApi("/integration/list", request, GetIntegrationListResponse.class);
    }

    @Override
    public List<Integration> getIntegrationList() throws PowerAuthClientException {
        return this.getIntegrationList(new GetIntegrationListRequest()).getItems();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/integration/remove", request, com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse removeIntegration(String id) throws PowerAuthClientException {
        RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return this.removeIntegration(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/create", request, com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse createCallbackUrl(Long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException {
        CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        return this.createCallbackUrl(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/update", request, com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateCallbackUrlResponse updateCallbackUrl(String id, long applicationId, String name, String callbackUrl, List<String> attributes) throws PowerAuthClientException {
        UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId(id);
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        return this.updateCallbackUrl(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/list", request, com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse.class);
    }

    @Override
    public List<CallbackUrl> getCallbackUrlList(Long applicationId) throws PowerAuthClientException {
        GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request).getCallbackUrlList();
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/remove", request, com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws PowerAuthClientException {
        RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateTokenResponse createToken(CreateTokenRequest request) throws PowerAuthClientException {
        return callV3RestApi("/token/create", request, com.wultra.security.powerauth.client.model.response.CreateTokenResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                               String encryptedData, String mac, String nonce, SignatureType signatureType) throws PowerAuthClientException {
        CreateTokenRequest request = new CreateTokenRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setNonce(nonce);
        request.setSignatureType(signatureType);
        return createToken(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException {
        return callV3RestApi("/token/validate", request, com.wultra.security.powerauth.client.model.response.ValidateTokenResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws PowerAuthClientException {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setTokenDigest(tokenDigest);
        return validateToken(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveTokenResponse removeToken(RemoveTokenRequest request) throws PowerAuthClientException {
        return callV3RestApi("/token/remove", request, com.wultra.security.powerauth.client.model.response.RemoveTokenResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException {
        RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws PowerAuthClientException {
        return callV3RestApi("/ecies/decryptor", request, com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthClientException {
        GetEciesDecryptorRequest request = new GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        return getEciesDecryptor(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException {
        return callV3RestApi("/upgrade/start", request, com.wultra.security.powerauth.client.model.response.StartUpgradeResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                                 String encryptedData, String mac, String nonce) throws PowerAuthClientException {
        StartUpgradeRequest request = new StartUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return startUpgrade(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws PowerAuthClientException {
        return callV3RestApi("/upgrade/commit", request, com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException {
        CommitUpgradeRequest request = new CommitUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitUpgrade(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/create", request, com.wultra.security.powerauth.client.model.response.CreateRecoveryCodeResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.CreateRecoveryCodeResponse createRecoveryCode(Long applicationId, String userId, Long pukCount) throws PowerAuthClientException {
        CreateRecoveryCodeRequest request = new CreateRecoveryCodeRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setPukCount(pukCount);
        return createRecoveryCode(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/confirm", request, com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                                                                               String encryptedData, String mac, String nonce) throws PowerAuthClientException {
        ConfirmRecoveryCodeRequest request = new ConfirmRecoveryCodeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return confirmRecoveryCode(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/lookup", request, com.wultra.security.powerauth.client.model.response.LookupRecoveryCodesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, Long applicationId,
                                                                                                               com.wultra.security.powerauth.client.model.enumeration.RecoveryCodeStatus recoveryCodeStatus, com.wultra.security.powerauth.client.model.enumeration.RecoveryPukStatus recoveryPukStatus) throws PowerAuthClientException {
        LookupRecoveryCodesRequest request = new LookupRecoveryCodesRequest();
        request.setUserId(userId);
        request.setActivationId(activationId);
        request.setApplicationId(applicationId);
        request.setRecoveryCodeStatus(recoveryCodeStatus);
        request.setRecoveryPukStatus(recoveryPukStatus);
        return lookupRecoveryCodes(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/revoke", request, com.wultra.security.powerauth.client.model.response.RevokeRecoveryCodesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) throws PowerAuthClientException {
        RevokeRecoveryCodesRequest request = new RevokeRecoveryCodesRequest();
        request.getRecoveryCodeIds().addAll(recoveryCodeIds);
        return revokeRecoveryCodes(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/recovery/create", request, com.wultra.security.powerauth.client.model.response.RecoveryCodeActivationResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                                                                                String ephemeralPublicKey, String encryptedData, String mac, String nonce) throws PowerAuthClientException {
        RecoveryCodeActivationRequest request = new RecoveryCodeActivationRequest();
        request.setRecoveryCode(recoveryCode);
        request.setPuk(puk);
        request.setApplicationKey(applicationKey);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        return createActivationUsingRecoveryCode(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/config/detail", request, com.wultra.security.powerauth.client.model.response.GetRecoveryConfigResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.GetRecoveryConfigResponse getRecoveryConfig(Long applicationId) throws PowerAuthClientException {
        GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return getRecoveryConfig(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws PowerAuthClientException {
        return callV3RestApi("/recovery/config/update", request, com.wultra.security.powerauth.client.model.response.UpdateRecoveryConfigResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateRecoveryConfigResponse updateRecoveryConfig(Long applicationId, Boolean activationRecoveryEnabled, Boolean recoveryPostcardEnabled, Boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) throws PowerAuthClientException {
        UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        request.setActivationRecoveryEnabled(activationRecoveryEnabled);
        request.setRecoveryPostcardEnabled(recoveryPostcardEnabled);
        request.setAllowMultipleRecoveryCodes(allowMultipleRecoveryCodes);
        request.setRemotePostcardPublicKey(remoteRecoveryPublicKeyBase64);
        return updateRecoveryConfig(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/list", request, com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse listActivationFlags(String activationId) throws PowerAuthClientException {
        ListActivationFlagsRequest request = new ListActivationFlagsRequest();
        request.setActivationId(activationId);
        return listActivationFlags(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/create", request, com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        AddActivationFlagsRequest request = new AddActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return addActivationFlags(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/update", request, com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        UpdateActivationFlagsRequest request = new UpdateActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return updateActivationFlags(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/remove", request, com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        RemoveActivationFlagsRequest request = new RemoveActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return removeActivationFlags(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/list", request, com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse listApplicationRoles(Long applicationId) throws PowerAuthClientException {
        ListApplicationRolesRequest request = new ListApplicationRolesRequest();
        request.setApplicationId(applicationId);
        return listApplicationRoles(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/create", request, com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse addApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        AddApplicationRolesRequest request = new AddApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return addApplicationRoles(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/update", request, com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse updateApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        UpdateApplicationRolesRequest request = new UpdateApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return updateApplicationRoles(request);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/remove", request, com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse.class);
    }

    @Override
    public com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse removeApplicationRoles(Long applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        RemoveApplicationRolesRequest request = new RemoveApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return removeApplicationRoles(request);
    }

    @Override
    public OperationDetailResponse createOperation(OperationCreateRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/create", request, OperationDetailResponse.class);
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/detail", request, OperationDetailResponse.class);
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/list", request, OperationListResponse.class);
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/list/pending", request, OperationListResponse.class);
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/cancel", request, OperationDetailResponse.class);
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/approve", request, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/approve/fail", request, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException {
        return callV3RestApi("/operation/reject", request, OperationUserActionResponse.class);
    }

}
