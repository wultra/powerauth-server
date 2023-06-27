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
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
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
    private static final MultiValueMap<String, String> EMPTY_MULTI_MAP = new LinkedMultiValueMap<>();

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
        final DefaultRestClient.Builder builder = DefaultRestClient.builder().baseUrl(baseUrl)
                .acceptInvalidCertificate(config.getAcceptInvalidSslCertificate())
                .connectionTimeout(config.getConnectTimeout())
                .maxInMemorySize(config.getMaxMemorySize());
        if (config.isProxyEnabled()) {
            final DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(config.getProxyHost()).port(config.getProxyPort());
            if (config.getProxyUsername() != null) {
                proxyBuilder.username(config.getProxyUsername()).password(config.getProxyPassword());
            }
            proxyBuilder.build();
        }
        if (config.getPowerAuthClientToken() != null) {
            builder.httpBasicAuth().username(config.getPowerAuthClientToken()).password(config.getPowerAuthClientSecret()).build();
        }
        if (config.getDefaultHttpHeaders() != null) {
            builder.defaultHttpHeaders(config.getDefaultHttpHeaders());
        }
        if (config.getFilter() != null) {
            builder.filter(config.getFilter());
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
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @param responseType Response type.
     * @return Response.
     */
    private <T> T callV3RestApi(String path, Object request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders, Class<T> responseType) throws PowerAuthClientException {
        final ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
        try {
            final ObjectResponse<T> objectResponse = restClient.postObject(PA_REST_V3_PREFIX + path, objectRequest, queryParams, httpHeaders, responseType);
            return objectResponse.getResponseObject();
        } catch (RestClientException ex) {
            if (ex.getStatusCode() == null) {
                // Logging for network errors when port is closed
                logger.warn("PowerAuth service is not accessible, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
            } else if (ex.getStatusCode() == HttpStatus.NOT_FOUND) {
                // Logging for 404 errors
                logger.warn("PowerAuth service is not available, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
            } else if (ex.getStatusCode() == HttpStatus.BAD_REQUEST) {
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
            final TypeReference<ObjectResponse<PowerAuthError>> typeReference = new TypeReference<>(){};
            final ObjectResponse<PowerAuthError> error = objectMapper.readValue(ex.getResponse(), typeReference);
            if (error == null || error.getResponseObject() == null) {
                throw new PowerAuthClientException("Invalid response object");
            }
            if ("ERR_RECOVERY".equals(error.getResponseObject().getCode())) {
                // In case of special recovery errors, return PowerAuthErrorRecovery which includes additional information about recovery
                final TypeReference<ObjectResponse<PowerAuthErrorRecovery>> PowerAuthErrorRecovery = new TypeReference<>(){};
                final ObjectResponse<PowerAuthErrorRecovery> errorRecovery = objectMapper.readValue(ex.getResponse(), PowerAuthErrorRecovery);
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

    @Override
    public GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException {
        return getSystemStatus(EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetSystemStatusResponse getSystemStatus(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/status", null, queryParams, httpHeaders, GetSystemStatusResponse.class);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException {
        return getErrorList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/error/list", request, queryParams, httpHeaders, GetErrorCodeListResponse.class);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(String language) throws PowerAuthClientException {
        final GetErrorCodeListRequest request = new GetErrorCodeListRequest();
        request.setLanguage(language);
        return getErrorList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public InitActivationResponse initActivation(InitActivationRequest request) throws PowerAuthClientException {
        return initActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public InitActivationResponse initActivation(InitActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/init", request, queryParams, httpHeaders, InitActivationResponse.class);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId) throws PowerAuthClientException {
        return initActivation(userId, applicationId, null, null, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId, ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
        return initActivation(userId, applicationId, null, null, otpValidation, otp);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException {
        return initActivation(userId, applicationId, maxFailureCount, timestampActivationExpire, ActivationOtpValidation.NONE, null);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId, Long maxFailureCount, Date timestampActivationExpire,
                                                 ActivationOtpValidation otpValidation, String otp) throws PowerAuthClientException {
        final InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setActivationOtpValidation(otpValidation);
        request.setActivationOtp(otp);
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(timestampActivationExpire);
        }
        return initActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException {
        return prepareActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/prepare", request, queryParams, httpHeaders, PrepareActivationResponse.class);
    }

    @Override
    public PrepareActivationResponse prepareActivation(String activationCode, String applicationKey, boolean shouldGenerateRecoveryCodes, String ephemeralPublicKey, String encryptedData, String mac, String nonce, String protocolVersion, Long timestamp) throws PowerAuthClientException {
        final PrepareActivationRequest request = new PrepareActivationRequest();
        request.setActivationCode(activationCode);
        request.setApplicationKey(applicationKey);
        request.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return prepareActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException {
        return createActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateActivationResponse createActivation(CreateActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/create", request, queryParams, httpHeaders, CreateActivationResponse.class);
    }

    @Override
    public CreateActivationResponse createActivation(String userId, Date timestampActivationExpire, Long maxFailureCount,
                                                     String applicationKey, String ephemeralPublicKey, String encryptedData,
                                                     String mac, String nonce, String protocolVersion, Long timestamp) throws PowerAuthClientException {
        final CreateActivationRequest request = new CreateActivationRequest();
        request.setUserId(userId);
        if (timestampActivationExpire != null) {
            request.setTimestampActivationExpire(timestampActivationExpire);
        }
        if (maxFailureCount != null) {
            request.setMaxFailureCount(maxFailureCount);
        }
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return createActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        final UpdateActivationOtpRequest request = new UpdateActivationOtpRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return updateActivationOtp(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitActivationResponse commitActivation(CommitActivationRequest request) throws PowerAuthClientException {
        return commitActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/otp/update", request, queryParams, httpHeaders, UpdateActivationOtpResponse.class);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException {
        return updateActivationOtp(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitActivationResponse commitActivation(CommitActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/commit", request, queryParams, httpHeaders, CommitActivationResponse.class);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        final CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return commitActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitActivationResponse commitActivation(String activationId, String externalUserId, String activationOtp) throws PowerAuthClientException {
        final CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setActivationOtp(activationOtp);
        return commitActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException {
        return getActivationStatus(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/status", request, queryParams, httpHeaders, GetActivationStatusResponse.class);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException {
        final GetActivationStatusResponse response = this.getActivationStatusWithEncryptedStatusBlob(activationId, null);
        response.setEncryptedStatusBlob(null);
        return response;
    }

    @Override
    public GetActivationStatusResponse getActivationStatusWithEncryptedStatusBlob(String activationId, String challenge) throws PowerAuthClientException {
        final GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        request.setChallenge(challenge);
        return getActivationStatus(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException {
        return removeActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/remove", request, queryParams, httpHeaders, RemoveActivationResponse.class);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        return removeActivation(activationId, externalUserId, false);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId, boolean revokeRecoveryCodes) throws PowerAuthClientException {
        final RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        request.setRevokeRecoveryCodes(revokeRecoveryCodes);
        return removeActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException {
        return getActivationListForUser(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/list", request, queryParams, httpHeaders, GetActivationListForUserResponse.class);
    }

    @Override
    public List<Activation> getActivationListForUser(String userId) throws PowerAuthClientException {
        final GetActivationListForUserRequest request = new GetActivationListForUserRequest();
        request.setUserId(userId);
        return getActivationListForUser(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP).getActivations();
    }

    @Override
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request) throws PowerAuthClientException {
        return lookupActivations(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public LookupActivationsResponse lookupActivations(LookupActivationsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/lookup", request, queryParams, httpHeaders, LookupActivationsResponse.class);
    }

    @Override
    public List<Activation> lookupActivations(List<String> userIds, List<String> applicationIds, Date timestampLastUsedBefore, Date timestampLastUsedAfter, ActivationStatus activationStatus, List<String> activationFlags) throws PowerAuthClientException {
        final LookupActivationsRequest request = new LookupActivationsRequest();
        request.getUserIds().addAll(userIds);
        if (applicationIds != null) {
            request.getApplicationIds().addAll(applicationIds);
        }
        if (timestampLastUsedBefore != null) {
            request.setTimestampLastUsedBefore(timestampLastUsedBefore);
        }
        if (timestampLastUsedAfter != null) {
            request.setTimestampLastUsedAfter(timestampLastUsedAfter);
        }
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        if (activationFlags != null) {
            request.getActivationFlags().addAll(activationFlags);
        }
        return lookupActivations(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP).getActivations();
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request) throws PowerAuthClientException {
        return updateStatusForActivations(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(UpdateStatusForActivationsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/status/update", request, queryParams, httpHeaders, UpdateStatusForActivationsResponse.class);
    }

    @Override
    public UpdateStatusForActivationsResponse updateStatusForActivations(List<String> activationIds, ActivationStatus activationStatus) throws PowerAuthClientException {
        final UpdateStatusForActivationsRequest request = new UpdateStatusForActivationsRequest();
        request.getActivationIds().addAll(activationIds);
        if (activationStatus != null) {
            request.setActivationStatus(activationStatus);
        }
        return updateStatusForActivations(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) throws PowerAuthClientException {
        return verifySignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/verify", request, queryParams, httpHeaders, VerifySignatureResponse.class);
    }

    @Override
    public VerifySignatureResponse verifySignature(String activationId, String applicationKey, String data, String signature, SignatureType signatureType, String signatureVersion, Long forcedSignatureVersion) throws PowerAuthClientException {
        final VerifySignatureRequest request = new VerifySignatureRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setSignature(signature);
        request.setSignatureType(signatureType);
        request.setSignatureVersion(signatureVersion);
        request.setForcedSignatureVersion(forcedSignatureVersion);
        return verifySignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return createPersonalizedOfflineSignaturePayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(CreatePersonalizedOfflineSignaturePayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/personalized/create", request, queryParams, httpHeaders, CreatePersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public CreatePersonalizedOfflineSignaturePayloadResponse createPersonalizedOfflineSignaturePayload(String activationId, String data) throws PowerAuthClientException {
        CreatePersonalizedOfflineSignaturePayloadRequest request = new CreatePersonalizedOfflineSignaturePayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineSignaturePayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request) throws PowerAuthClientException {
        return createNonPersonalizedOfflineSignaturePayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(CreateNonPersonalizedOfflineSignaturePayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/non-personalized/create", request, queryParams, httpHeaders, CreateNonPersonalizedOfflineSignaturePayloadResponse.class);
    }

    @Override
    public CreateNonPersonalizedOfflineSignaturePayloadResponse createNonPersonalizedOfflineSignaturePayload(String applicationId, String data) throws PowerAuthClientException {
        final CreateNonPersonalizedOfflineSignaturePayloadRequest request = new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineSignaturePayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request) throws PowerAuthClientException {
        return verifyOfflineSignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(VerifyOfflineSignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/offline/verify", request, queryParams, httpHeaders, VerifyOfflineSignatureResponse.class);
    }

    @Override
    public VerifyOfflineSignatureResponse verifyOfflineSignature(String activationId, String data, String signature, boolean allowBiometry) throws PowerAuthClientException {
        final VerifyOfflineSignatureRequest request = new VerifyOfflineSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineSignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException {
        return unlockVault(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/vault/unlock", request, queryParams, httpHeaders, VaultUnlockResponse.class);
    }

    @Override
    public VaultUnlockResponse unlockVault(String activationId, String applicationKey, String signature,
                                           SignatureType signatureType, String signatureVersion, String signedData,
                                           String ephemeralPublicKey, String encryptedData, String mac, String nonce,
                                           Long timestamp) throws PowerAuthClientException {
        final VaultUnlockRequest request = new VaultUnlockRequest();
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
        request.setTimestamp(timestamp);
        return unlockVault(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request) throws PowerAuthClientException {
        return verifyECDSASignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(VerifyECDSASignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/ecdsa/verify", request, queryParams, httpHeaders, VerifyECDSASignatureResponse.class);
    }

    @Override
    public VerifyECDSASignatureResponse verifyECDSASignature(String activationId, String data, String signature) throws PowerAuthClientException {
        final VerifyECDSASignatureRequest request = new VerifyECDSASignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return verifyECDSASignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException {
        return getSignatureAuditLog(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/signature/list", request, queryParams, httpHeaders, SignatureAuditResponse.class);
    }

    @Override
    public List<SignatureAuditItem> getSignatureAuditLog(String userId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        final SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setTimestampFrom(startingDate);
        request.setTimestampTo(endingDate);
        return getSignatureAuditLog(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP).getItems();
    }

    @Override
    public List<SignatureAuditItem> getSignatureAuditLog(String userId, String applicationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        final SignatureAuditRequest request = new SignatureAuditRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setTimestampFrom(startingDate);
        request.setTimestampTo(endingDate);
        return getSignatureAuditLog(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP).getItems();
    }

    @Override
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request) throws PowerAuthClientException {
        return getActivationHistory(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ActivationHistoryResponse getActivationHistory(ActivationHistoryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/history", request, queryParams, httpHeaders, ActivationHistoryResponse.class);
    }

    @Override
    public List<ActivationHistoryItem> getActivationHistory(String activationId, Date startingDate, Date endingDate) throws PowerAuthClientException {
        final ActivationHistoryRequest request = new ActivationHistoryRequest();
        request.setActivationId(activationId);
        request.setTimestampFrom(startingDate);
        request.setTimestampTo(endingDate);
        return getActivationHistory(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP).getItems();
    }

    @Override
    public BlockActivationResponse blockActivation(BlockActivationRequest request) throws PowerAuthClientException {
        return blockActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public BlockActivationResponse blockActivation(BlockActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/block", request, queryParams, httpHeaders, BlockActivationResponse.class);
    }

    @Override
    public BlockActivationResponse blockActivation(String activationId, String reason, String externalUserId) throws PowerAuthClientException {
        final BlockActivationRequest request = new BlockActivationRequest();
        request.setActivationId(activationId);
        request.setReason(reason);
        request.setExternalUserId(externalUserId);
        return blockActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) throws PowerAuthClientException {
        return unblockActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/unblock", request, queryParams, httpHeaders, UnblockActivationResponse.class);
    }

    @Override
    public UnblockActivationResponse unblockActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        final UnblockActivationRequest request = new UnblockActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return unblockActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetApplicationListResponse getApplicationList() throws PowerAuthClientException {
        return getApplicationList(EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetApplicationListResponse getApplicationList(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/list", null, queryParams, httpHeaders, GetApplicationListResponse.class);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException {
        return getApplicationDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/detail", request, queryParams, httpHeaders, GetApplicationDetailResponse.class);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(String applicationId) throws PowerAuthClientException {
        final GetApplicationDetailRequest request = new GetApplicationDetailRequest();
        request.setApplicationId(applicationId);
        return getApplicationDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request) throws PowerAuthClientException {
        return lookupApplicationByAppKey(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(LookupApplicationByAppKeyRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/detail/version", request, queryParams, httpHeaders, LookupApplicationByAppKeyResponse.class);
    }

    @Override
    public LookupApplicationByAppKeyResponse lookupApplicationByAppKey(String applicationKey) throws PowerAuthClientException {
        final LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);
        return lookupApplicationByAppKey(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateApplicationResponse createApplication(CreateApplicationRequest request) throws PowerAuthClientException {
        return createApplication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateApplicationResponse createApplication(CreateApplicationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/create", request, queryParams, httpHeaders, CreateApplicationResponse.class);
    }

    @Override
    public CreateApplicationResponse createApplication(String name) throws PowerAuthClientException {
        final CreateApplicationRequest request = new CreateApplicationRequest();
        request.setApplicationId(name);
        return createApplication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request) throws PowerAuthClientException {
        return createApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(CreateApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/version/create", request, queryParams, httpHeaders, CreateApplicationVersionResponse.class);
    }

    @Override
    public CreateApplicationVersionResponse createApplicationVersion(String applicationId, String versionName) throws PowerAuthClientException {
        final CreateApplicationVersionRequest request = new CreateApplicationVersionRequest();
        request.setApplicationId(applicationId);
        request.setApplicationVersionId(versionName);
        return createApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request) throws PowerAuthClientException {
        return unsupportApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(UnsupportApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/version/unsupport", request, queryParams, httpHeaders, UnsupportApplicationVersionResponse.class);
    }

    @Override
    public UnsupportApplicationVersionResponse unsupportApplicationVersion(String appId, String versionId) throws PowerAuthClientException {
        final UnsupportApplicationVersionRequest request = new UnsupportApplicationVersionRequest();
        request.setApplicationId(appId);
        request.setApplicationVersionId(versionId);
        return unsupportApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request) throws PowerAuthClientException {
        return supportApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(SupportApplicationVersionRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/version/support", request, queryParams, httpHeaders, SupportApplicationVersionResponse.class);
    }

    @Override
    public SupportApplicationVersionResponse supportApplicationVersion(String appId, String versionId) throws PowerAuthClientException {
        final SupportApplicationVersionRequest request = new SupportApplicationVersionRequest();
        request.setApplicationId(appId);
        request.setApplicationVersionId(versionId);
        return supportApplicationVersion(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws PowerAuthClientException {
        return createIntegration(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/integration/create", request, queryParams, httpHeaders, CreateIntegrationResponse.class);
    }

    @Override
    public CreateIntegrationResponse createIntegration(String name) throws PowerAuthClientException {
        final CreateIntegrationRequest request = new CreateIntegrationRequest();
        request.setName(name);
        return createIntegration(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetIntegrationListResponse getIntegrationList() throws PowerAuthClientException {
        return getIntegrationList(EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetIntegrationListResponse getIntegrationList(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/integration/list", null, queryParams, httpHeaders, GetIntegrationListResponse.class);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException {
        return removeIntegration(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/integration/remove", request, queryParams, httpHeaders, RemoveIntegrationResponse.class);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(String id) throws PowerAuthClientException {
        final RemoveIntegrationRequest request = new RemoveIntegrationRequest();
        request.setId(id);
        return removeIntegration(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request) throws PowerAuthClientException {
        return createCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(CreateCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/create", request, queryParams, httpHeaders, CreateCallbackUrlResponse.class);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(String applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication) throws PowerAuthClientException {
        final CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setType(type.toString());
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        request.setAuthentication(authentication);
        return createCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException {
        return updateCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/update", request, queryParams, httpHeaders, UpdateCallbackUrlResponse.class);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(String id, String applicationId, String name, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication) throws PowerAuthClientException {
        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId(id);
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        request.setAuthentication(authentication);
        return updateCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetCallbackUrlListResponse getCallbackUrlList(String applicationId) throws PowerAuthClientException {
        final GetCallbackUrlListRequest request = new GetCallbackUrlListRequest();
        request.setApplicationId(applicationId);
        return getCallbackUrlList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetCallbackUrlListResponse getCallbackUrlList(GetCallbackUrlListRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/list", request, queryParams, httpHeaders, GetCallbackUrlListResponse.class);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException {
        return removeCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/callback/remove", request, queryParams, httpHeaders, RemoveCallbackUrlResponse.class);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(String callbackUrlId) throws PowerAuthClientException {
        final RemoveCallbackUrlRequest request = new RemoveCallbackUrlRequest();
        request.setId(callbackUrlId);
        return removeCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateTokenResponse createToken(CreateTokenRequest request) throws PowerAuthClientException {
        return createToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateTokenResponse createToken(CreateTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/token/create", request, queryParams, httpHeaders, CreateTokenResponse.class);
    }

    @Override
    public CreateTokenResponse createToken(String activationId, String applicationKey, String ephemeralPublicKey,
                                           String encryptedData, String mac, String nonce, String protocolVersion,
                                           Long timestamp, SignatureType signatureType) throws PowerAuthClientException {
        final CreateTokenRequest request = new CreateTokenRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        request.setSignatureType(signatureType);
        return createToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException {
        return validateToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/token/validate", request, queryParams, httpHeaders, ValidateTokenResponse.class);
    }

    @Override
    public ValidateTokenResponse validateToken(String tokenId, String nonce, long timestamp, String tokenDigest) throws PowerAuthClientException {
        final ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setTimestamp(timestamp);
        request.setTokenDigest(tokenDigest);
        return validateToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveTokenResponse removeToken(RemoveTokenRequest request) throws PowerAuthClientException {
        return removeToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveTokenResponse removeToken(RemoveTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/token/remove", request, queryParams, httpHeaders, RemoveTokenResponse.class);
    }

    @Override
    public RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException {
        final RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request) throws PowerAuthClientException {
        return getEciesDecryptor(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(GetEciesDecryptorRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/ecies/decryptor", request, queryParams, httpHeaders, GetEciesDecryptorResponse.class);
    }

    @Override
    public GetEciesDecryptorResponse getEciesDecryptor(String activationId, String applicationKey, String ephemeralPublicKey,
                                                       String nonce, String protocolVersion, Long timestamp) throws PowerAuthClientException {
        final GetEciesDecryptorRequest request = new GetEciesDecryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return getEciesDecryptor(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException {
        return startUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/upgrade/start", request, queryParams, httpHeaders, StartUpgradeResponse.class);
    }

    @Override
    public StartUpgradeResponse startUpgrade(String activationId, String applicationKey, String ephemeralPublicKey,
                                             String encryptedData, String mac, String nonce, String protocolVersion,
                                             Long timestamp) throws PowerAuthClientException {
        final StartUpgradeRequest request = new StartUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return startUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request) throws PowerAuthClientException {
        return commitUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(CommitUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/upgrade/commit", request, queryParams, httpHeaders, CommitUpgradeResponse.class);
    }

    @Override
    public CommitUpgradeResponse commitUpgrade(String activationId, String applicationKey) throws PowerAuthClientException {
        final CommitUpgradeRequest request = new CommitUpgradeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        return commitUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request) throws PowerAuthClientException {
        return createRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(CreateRecoveryCodeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/create", request, queryParams, httpHeaders, CreateRecoveryCodeResponse.class);
    }

    @Override
    public CreateRecoveryCodeResponse createRecoveryCode(String applicationId, String userId, Long pukCount) throws PowerAuthClientException {
        final CreateRecoveryCodeRequest request = new CreateRecoveryCodeRequest();
        request.setApplicationId(applicationId);
        request.setUserId(userId);
        request.setPukCount(pukCount);
        return createRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request) throws PowerAuthClientException {
        return confirmRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(ConfirmRecoveryCodeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/confirm", request, queryParams, httpHeaders, ConfirmRecoveryCodeResponse.class);
    }

    @Override
    public ConfirmRecoveryCodeResponse confirmRecoveryCode(String activationId, String applicationKey, String ephemeralPublicKey,
                                                           String encryptedData, String mac, String nonce, String protocolVersion,
                                                           Long timestamp) throws PowerAuthClientException {
        final ConfirmRecoveryCodeRequest request = new ConfirmRecoveryCodeRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setEphemeralPublicKey(ephemeralPublicKey);
        request.setEncryptedData(encryptedData);
        request.setMac(mac);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return confirmRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request) throws PowerAuthClientException {
        return lookupRecoveryCodes(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(LookupRecoveryCodesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/lookup", request, queryParams, httpHeaders, LookupRecoveryCodesResponse.class);
    }

    @Override
    public LookupRecoveryCodesResponse lookupRecoveryCodes(String userId, String activationId, String applicationId,
                                                           RecoveryCodeStatus recoveryCodeStatus, RecoveryPukStatus recoveryPukStatus) throws PowerAuthClientException {
        final LookupRecoveryCodesRequest request = new LookupRecoveryCodesRequest();
        request.setUserId(userId);
        request.setActivationId(activationId);
        request.setApplicationId(applicationId);
        request.setRecoveryCodeStatus(recoveryCodeStatus);
        request.setRecoveryPukStatus(recoveryPukStatus);
        return lookupRecoveryCodes(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request) throws PowerAuthClientException {
        return revokeRecoveryCodes(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(RevokeRecoveryCodesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/revoke", request, queryParams, httpHeaders, RevokeRecoveryCodesResponse.class);
    }

    @Override
    public RevokeRecoveryCodesResponse revokeRecoveryCodes(List<Long> recoveryCodeIds) throws PowerAuthClientException {
        final RevokeRecoveryCodesRequest request = new RevokeRecoveryCodesRequest();
        request.getRecoveryCodeIds().addAll(recoveryCodeIds);
        return revokeRecoveryCodes(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request) throws PowerAuthClientException {
        return createActivationUsingRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(RecoveryCodeActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/recovery/create", request, queryParams, httpHeaders, RecoveryCodeActivationResponse.class);
    }

    @Override
    public RecoveryCodeActivationResponse createActivationUsingRecoveryCode(String recoveryCode, String puk, String applicationKey, Long maxFailureCount,
                                                                            String ephemeralPublicKey, String encryptedData, String mac, String nonce,
                                                                            String protocolVersion, Long timestamp) throws PowerAuthClientException {
        final RecoveryCodeActivationRequest request = new RecoveryCodeActivationRequest();
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
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        return createActivationUsingRecoveryCode(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request) throws PowerAuthClientException {
        return getRecoveryConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(GetRecoveryConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/config/detail", request, queryParams, httpHeaders, GetRecoveryConfigResponse.class);
    }

    @Override
    public GetRecoveryConfigResponse getRecoveryConfig(String applicationId) throws PowerAuthClientException {
        final GetRecoveryConfigRequest request = new GetRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        return getRecoveryConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request) throws PowerAuthClientException {
        return updateRecoveryConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(UpdateRecoveryConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/recovery/config/update", request, queryParams, httpHeaders, UpdateRecoveryConfigResponse.class);
    }

    @Override
    public UpdateRecoveryConfigResponse updateRecoveryConfig(String applicationId, boolean activationRecoveryEnabled, boolean recoveryPostcardEnabled, boolean allowMultipleRecoveryCodes, String remoteRecoveryPublicKeyBase64) throws PowerAuthClientException {
        final UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
        request.setApplicationId(applicationId);
        request.setActivationRecoveryEnabled(activationRecoveryEnabled);
        request.setRecoveryPostcardEnabled(recoveryPostcardEnabled);
        request.setAllowMultipleRecoveryCodes(allowMultipleRecoveryCodes);
        request.setRemotePostcardPublicKey(remoteRecoveryPublicKeyBase64);
        return updateRecoveryConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException {
        return listActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/list", request, queryParams, httpHeaders, ListActivationFlagsResponse.class);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(String activationId) throws PowerAuthClientException {
        final ListActivationFlagsRequest request = new ListActivationFlagsRequest();
        request.setActivationId(activationId);
        return listActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws PowerAuthClientException {
        return addActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/create", request, queryParams, httpHeaders, AddActivationFlagsResponse.class);
    }

    @Override
    public AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        final AddActivationFlagsRequest request = new AddActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return addActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws PowerAuthClientException {
        return updateActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/update", request, queryParams, httpHeaders, UpdateActivationFlagsResponse.class);
    }

    @Override
    public UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        final UpdateActivationFlagsRequest request = new UpdateActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return updateActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws PowerAuthClientException {
        return removeActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/activation/flags/remove", request, queryParams, httpHeaders, RemoveActivationFlagsResponse.class);
    }

    @Override
    public RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws PowerAuthClientException {
        final RemoveActivationFlagsRequest request = new RemoveActivationFlagsRequest();
        request.setActivationId(activationId);
        request.getActivationFlags().addAll(activationFlags);
        return removeActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws PowerAuthClientException {
        return listApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/list", request, queryParams, httpHeaders, ListApplicationRolesResponse.class);
    }

    @Override
    public ListApplicationRolesResponse listApplicationRoles(String applicationId) throws PowerAuthClientException {
        final ListApplicationRolesRequest request = new ListApplicationRolesRequest();
        request.setApplicationId(applicationId);
        return listApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws PowerAuthClientException {
        return addApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/create", request, queryParams, httpHeaders, AddApplicationRolesResponse.class);
    }

    @Override
    public AddApplicationRolesResponse addApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        final AddApplicationRolesRequest request = new AddApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return addApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws PowerAuthClientException {
        return updateApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/update", request, queryParams, httpHeaders, UpdateApplicationRolesResponse.class);
    }

    @Override
    public UpdateApplicationRolesResponse updateApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        final UpdateApplicationRolesRequest request = new UpdateApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return updateApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws PowerAuthClientException {
        return removeApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/application/roles/remove", request, queryParams, httpHeaders, RemoveApplicationRolesResponse.class);
    }

    @Override
    public RemoveApplicationRolesResponse removeApplicationRoles(String applicationId, List<String> applicationRoles) throws PowerAuthClientException {
        final RemoveApplicationRolesRequest request = new RemoveApplicationRolesRequest();
        request.setApplicationId(applicationId);
        request.getApplicationRoles().addAll(applicationRoles);
        return removeApplicationRoles(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse createOperation(OperationCreateRequest request) throws PowerAuthClientException {
        return createOperation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse createOperation(OperationCreateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/create", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException {
        return operationDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/detail", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException {
        return operationList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/list", request, queryParams, httpHeaders, OperationListResponse.class);
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException {
        return operationPendingList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/list/pending", request, queryParams, httpHeaders, OperationListResponse.class);
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException {
        return operationCancel(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/cancel", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException {
        return operationApprove(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/approve", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws PowerAuthClientException {
        return failApprovalOperation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/approve/fail", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException {
        return operationReject(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/reject", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationTemplateListResponse operationTemplateList() throws PowerAuthClientException {
        return callV3RestApi("/operation/template/list", null, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, OperationTemplateListResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request) throws PowerAuthClientException {
        return operationTemplateDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/template/detail", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws PowerAuthClientException {
        return createOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/template/create", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws PowerAuthClientException {
        return updateOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/template/update", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public Response removeOperationTemplate(OperationTemplateDeleteRequest request) throws PowerAuthClientException {
        return removeOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public Response removeOperationTemplate(OperationTemplateDeleteRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/operation/template/remove", request, queryParams, httpHeaders, Response.class);
    }

    @Override
    public TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request) throws PowerAuthClientException {
        return requestTelemetryReport(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    public TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV3RestApi("/telemetry/report", request, queryParams, httpHeaders, TelemetryReportResponse.class);
    }

}
