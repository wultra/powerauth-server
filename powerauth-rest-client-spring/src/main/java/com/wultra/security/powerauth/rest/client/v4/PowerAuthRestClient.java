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
package com.wultra.security.powerauth.rest.client.v4;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.SignatureAuditItem;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.*;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
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

    private static final String PA_REST_V4_PREFIX = "/v4";
    private static final MultiValueMap<String, String> EMPTY_MULTI_MAP = new LinkedMultiValueMap<>();

    private final RestClient restClient;
    private final ObjectMapper objectMapper = JsonMapper.builder()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

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
                .acceptInvalidCertificate(config.isAcceptInvalidSslCertificate())
                .connectionTimeout(config.getConnectTimeout())
                .responseTimeout(config.getResponseTimeout())
                .maxIdleTime(config.getMaxIdleTime())
                .maxLifeTime(config.getMaxLifeTime())
                .maxInMemorySize(config.getMaxMemorySize());
        if (config.isProxyEnabled()) {
            final DefaultRestClient.ProxyBuilder proxyBuilder = builder.proxy().host(config.getProxyHost()).port(config.getProxyPort());
            if (config.getProxyUsername() != null) {
                proxyBuilder.username(config.getProxyUsername()).password(config.getProxyPassword());
            }
        }
        if (config.getPowerAuthClientToken() != null) {
            builder.httpBasicAuth().username(config.getPowerAuthClientToken()).password(config.getPowerAuthClientSecret());
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
     * Call the PowerAuth v4 API.
     *
     * @param path Path of the endpoint.
     * @param request Request object.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @param responseType Response type.
     * @return Response.
     */
    private <T> T callV4RestApi(String path, Object request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders, Class<T> responseType) throws PowerAuthClientException {
        final ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
        try {
            final ObjectResponse<T> objectResponse = restClient.postObject(PA_REST_V4_PREFIX + path, objectRequest, queryParams, httpHeaders, responseType);
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
            throw new PowerAuthClientException(error.getResponseObject().getMessage(), ex, error.getResponseObject());
        } catch (JacksonException ex2) {
            // Parsing failed, return a regular error
            logger.warn("Invalid response object, error: {}", ex2.getMessage());
            throw new PowerAuthClientException(ex.getMessage(), ex);
        }
    }

    @Override
    public GetSystemStatusResponse getSystemStatus() throws PowerAuthClientException {
        return getSystemStatus(EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetSystemStatusResponse getSystemStatus(MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/status", null, queryParams, httpHeaders, GetSystemStatusResponse.class);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request) throws PowerAuthClientException {
        return getErrorList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetErrorCodeListResponse getErrorList(GetErrorCodeListRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/error/list", request, queryParams, httpHeaders, GetErrorCodeListResponse.class);
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
        return callV4RestApi("/activation/init", request, queryParams, httpHeaders, InitActivationResponse.class);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId) throws PowerAuthClientException {
        final InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        return initActivation(request);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId, CommitPhase commitPhase, String otp) throws PowerAuthClientException {
        final InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setCommitPhase(commitPhase);
        request.setActivationOtp(otp);
        return initActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public InitActivationResponse initActivation(String userId, String applicationId, Long maxFailureCount, Date timestampActivationExpire) throws PowerAuthClientException {
        final InitActivationRequest request = new InitActivationRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        request.setMaxFailureCount(maxFailureCount);
        request.setTimestampActivationExpire(timestampActivationExpire);
        return initActivation(request);
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) throws PowerAuthClientException {
        return prepareActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/prepare", request, queryParams, httpHeaders, PrepareActivationResponse.class);
    }

    @Override
    public CreateActivationResponse createActivation(CreateActivationRequest request) throws PowerAuthClientException {
        return createActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateActivationResponse createActivation(CreateActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/create", request, queryParams, httpHeaders, CreateActivationResponse.class);
    }

    @Override
    public UpdateActivationNameResponse updateActivationName(UpdateActivationNameRequest request) throws PowerAuthClientException {
        return updateActivationName(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateActivationNameResponse updateActivationName(UpdateActivationNameRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/name/update", request, queryParams, httpHeaders, UpdateActivationNameResponse.class);
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
        return callV4RestApi("/activation/otp/update", request, queryParams, httpHeaders, UpdateActivationOtpResponse.class);
    }

    @Override
    public UpdateActivationOtpResponse updateActivationOtp(UpdateActivationOtpRequest request) throws PowerAuthClientException {
        return updateActivationOtp(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CommitActivationResponse commitActivation(CommitActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/commit", request, queryParams, httpHeaders, CommitActivationResponse.class);
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
    public Response confirmActivation(ConfirmActivationRequest request) throws PowerAuthClientException {
        return confirmActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public Response confirmActivation(ConfirmActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/confirm", request, queryParams, httpHeaders, Response.class);
    }

    @Override
    public Response confirmActivation(String activationId) throws PowerAuthClientException {
        final ConfirmActivationRequest request = new ConfirmActivationRequest();
        request.setActivationId(activationId);
        return confirmActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);

    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) throws PowerAuthClientException {
        return getActivationStatus(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/status", request, queryParams, httpHeaders, GetActivationStatusResponse.class);
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(String activationId) throws PowerAuthClientException {
        final GetActivationStatusRequest request = new GetActivationStatusRequest();
        request.setActivationId(activationId);
        return this.getActivationStatus(request);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) throws PowerAuthClientException {
        return removeActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/remove", request, queryParams, httpHeaders, RemoveActivationResponse.class);
    }

    @Override
    public RemoveActivationResponse removeActivation(String activationId, String externalUserId) throws PowerAuthClientException {
        final RemoveActivationRequest request = new RemoveActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(externalUserId);
        return removeActivation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request) throws PowerAuthClientException {
        return getActivationListForUser(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetActivationListForUserResponse getActivationListForUser(GetActivationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/list", request, queryParams, httpHeaders, GetActivationListForUserResponse.class);
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
        return callV4RestApi("/activation/lookup", request, queryParams, httpHeaders, LookupActivationsResponse.class);
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
        return callV4RestApi("/activation/status/update", request, queryParams, httpHeaders, UpdateStatusForActivationsResponse.class);
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
    public VerifyAuthenticationResponse verifyAuthentication(VerifyAuthenticationRequest request) throws PowerAuthClientException {
        return verifyAuthentication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyAuthenticationResponse verifyAuthentication(VerifyAuthenticationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/auth/verify", request, queryParams, httpHeaders, VerifyAuthenticationResponse.class);
    }

    @Override
    public VerifyAuthenticationResponse verifyAuthentication(String activationId, String applicationKey, String data, String authenticationCode, AuthenticationCodeType authenticationCodeType, String authenticationVersion) throws PowerAuthClientException {
        final VerifyAuthenticationRequest request = new VerifyAuthenticationRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setData(data);
        request.setAuthenticationCode(authenticationCode);
        request.setAuthenticationCodeType(authenticationCodeType);
        request.setAuthenticationVersion(authenticationVersion);
        return verifyAuthentication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(CreatePersonalizedOfflineAuthPayloadRequest request) throws PowerAuthClientException {
        return createPersonalizedOfflineAuthPayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(CreatePersonalizedOfflineAuthPayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/auth/offline/personalized/create", request, queryParams, httpHeaders, CreatePersonalizedOfflineAuthPayloadResponse.class);
    }

    @Override
    public CreatePersonalizedOfflineAuthPayloadResponse createPersonalizedOfflineAuthPayload(String activationId, String data) throws PowerAuthClientException {
        CreatePersonalizedOfflineAuthPayloadRequest request = new CreatePersonalizedOfflineAuthPayloadRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return createPersonalizedOfflineAuthPayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(CreateNonPersonalizedOfflineAuthPayloadRequest request) throws PowerAuthClientException {
        return createNonPersonalizedOfflineAuthPayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(CreateNonPersonalizedOfflineAuthPayloadRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/auth/offline/non-personalized/create", request, queryParams, httpHeaders, CreateNonPersonalizedOfflineAuthPayloadResponse.class);
    }

    @Override
    public CreateNonPersonalizedOfflineAuthPayloadResponse createNonPersonalizedOfflineAuthPayload(String applicationId, String data) throws PowerAuthClientException {
        final CreateNonPersonalizedOfflineAuthPayloadRequest request = new CreateNonPersonalizedOfflineAuthPayloadRequest();
        request.setApplicationId(applicationId);
        request.setData(data);
        return createNonPersonalizedOfflineAuthPayload(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(VerifyOfflineAuthenticationRequest request) throws PowerAuthClientException {
        return verifyOfflineAuthentication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(VerifyOfflineAuthenticationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/auth/offline/verify", request, queryParams, httpHeaders, VerifyOfflineAuthenticationResponse.class);
    }

    @Override
    public VerifyOfflineAuthenticationResponse verifyOfflineAuthentication(String activationId, String data, String authenticationCode, boolean allowBiometry) throws PowerAuthClientException {
        final VerifyOfflineAuthenticationRequest request = new VerifyOfflineAuthenticationRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setAuthenticationCode(authenticationCode);
        request.setAllowBiometry(allowBiometry);
        return verifyOfflineAuthentication(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request) throws PowerAuthClientException {
        return unlockVault(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VaultUnlockResponse unlockVault(VaultUnlockRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/vault/unlock", request, queryParams, httpHeaders, VaultUnlockResponse.class);
    }

    @Override
    public SignAsymmetricResponse signAsymmetric(SignAsymmetricRequest request) throws PowerAuthClientException {
        return signAsymmetric(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignAsymmetricResponse signAsymmetric(SignAsymmetricRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/dsa/sign", request, queryParams, httpHeaders, SignAsymmetricResponse.class);
    }

    @Override
    public SignAsymmetricResponse signAsymmetric(String activationId, String data) throws PowerAuthClientException {
        final SignAsymmetricRequest request = new SignAsymmetricRequest();
        request.setActivationId(activationId);
        request.setData(data);
        return signAsymmetric(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(VerifyAsymmetricSignatureRequest request) throws PowerAuthClientException {
        return verifyAsymmetricSignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(VerifyAsymmetricSignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/dsa/verify", request, queryParams, httpHeaders, VerifyAsymmetricSignatureResponse.class);
    }

    @Override
    public VerifyAsymmetricSignatureResponse verifyAsymmetricSignature(String activationId, String data, String signature) throws PowerAuthClientException {
        final VerifyAsymmetricSignatureRequest request = new VerifyAsymmetricSignatureRequest();
        request.setActivationId(activationId);
        request.setData(data);
        request.setSignature(signature);
        return verifyAsymmetricSignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignJwtResponse signJwt(SignJwtRequest request) throws PowerAuthClientException {
        return signJwt(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignJwtResponse signJwt(SignJwtRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/jwt/sign", request, queryParams, httpHeaders, SignJwtResponse.class);
    }

    @Override
    public VerifyJwtSignatureResponse verifyJwtSignature(VerifyJwtSignatureRequest request) throws PowerAuthClientException {
        return verifyJwtSignature(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public VerifyJwtSignatureResponse verifyJwtSignature(VerifyJwtSignatureRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/jwt/verify", request, queryParams, httpHeaders, VerifyJwtSignatureResponse.class);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request) throws PowerAuthClientException {
        return getSignatureAuditLog(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public SignatureAuditResponse getSignatureAuditLog(SignatureAuditRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/audit/list", request, queryParams, httpHeaders, SignatureAuditResponse.class);
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
        return callV4RestApi("/activation/history", request, queryParams, httpHeaders, ActivationHistoryResponse.class);
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
        return callV4RestApi("/activation/block", request, queryParams, httpHeaders, BlockActivationResponse.class);
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
        return callV4RestApi("/activation/unblock", request, queryParams, httpHeaders, UnblockActivationResponse.class);
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
        return callV4RestApi("/application/list", null, queryParams, httpHeaders, GetApplicationListResponse.class);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request) throws PowerAuthClientException {
        return getApplicationDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetApplicationDetailResponse getApplicationDetail(GetApplicationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/detail", request, queryParams, httpHeaders, GetApplicationDetailResponse.class);
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
        return callV4RestApi("/application/detail/version", request, queryParams, httpHeaders, LookupApplicationByAppKeyResponse.class);
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
        return callV4RestApi("/application/create", request, queryParams, httpHeaders, CreateApplicationResponse.class);
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
        return callV4RestApi("/application/version/create", request, queryParams, httpHeaders, CreateApplicationVersionResponse.class);
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
        return callV4RestApi("/application/version/unsupport", request, queryParams, httpHeaders, UnsupportApplicationVersionResponse.class);
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
        return callV4RestApi("/application/version/support", request, queryParams, httpHeaders, SupportApplicationVersionResponse.class);
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
        return callV4RestApi("/integration/create", request, queryParams, httpHeaders, CreateIntegrationResponse.class);
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
        return callV4RestApi("/integration/list", null, queryParams, httpHeaders, GetIntegrationListResponse.class);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws PowerAuthClientException {
        return removeIntegration(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/integration/remove", request, queryParams, httpHeaders, RemoveIntegrationResponse.class);
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
        return callV4RestApi("/application/callback/create", request, queryParams, httpHeaders, CreateCallbackUrlResponse.class);
    }

    @Override
    public CreateCallbackUrlResponse createCallbackUrl(String applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication, Duration retentionPeriod, Duration initialBackoff, Integer maxAttempts) throws PowerAuthClientException {
        final CreateCallbackUrlRequest request = new CreateCallbackUrlRequest();
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setType(type);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        request.setAuthentication(authentication);
        request.setRetentionPeriod(retentionPeriod);
        request.setInitialBackoff(initialBackoff);
        request.setMaxAttempts(maxAttempts);
        return createCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request) throws PowerAuthClientException {
        return updateCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(UpdateCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/callback/update", request, queryParams, httpHeaders, UpdateCallbackUrlResponse.class);
    }

    @Override
    public UpdateCallbackUrlResponse updateCallbackUrl(String id, String applicationId, String name, CallbackUrlType type, String callbackUrl, List<String> attributes, HttpAuthenticationPrivate authentication, Duration retentionPeriod, Duration initialBackoff, Integer maxAttempts) throws PowerAuthClientException {
        final UpdateCallbackUrlRequest request = new UpdateCallbackUrlRequest();
        request.setId(id);
        request.setApplicationId(applicationId);
        request.setName(name);
        request.setType(type);
        request.setCallbackUrl(callbackUrl);
        if (attributes != null) {
            request.getAttributes().addAll(attributes);
        }
        request.setAuthentication(authentication);
        request.setRetentionPeriod(retentionPeriod);
        request.setInitialBackoff(initialBackoff);
        request.setMaxAttempts(maxAttempts);
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
        return callV4RestApi("/application/callback/list", request, queryParams, httpHeaders, GetCallbackUrlListResponse.class);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request) throws PowerAuthClientException {
        return removeCallbackUrl(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public RemoveCallbackUrlResponse removeCallbackUrl(RemoveCallbackUrlRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/callback/remove", request, queryParams, httpHeaders, RemoveCallbackUrlResponse.class);
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
        return callV4RestApi("/token/create", request, queryParams, httpHeaders, CreateTokenResponse.class);
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) throws PowerAuthClientException {
        return validateToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/token/validate", request, queryParams, httpHeaders, ValidateTokenResponse.class);
    }

    @Override
    public ValidateTokenResponse validateToken(String tokenId, String nonce, String protocolVersion, long timestamp, String tokenDigest) throws PowerAuthClientException {
        final ValidateTokenRequest request = new ValidateTokenRequest();
        request.setTokenId(tokenId);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
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
        return callV4RestApi("/token/remove", request, queryParams, httpHeaders, RemoveTokenResponse.class);
    }

    @Override
    public RemoveTokenResponse removeToken(String tokenId, String activationId) throws PowerAuthClientException {
        final RemoveTokenRequest request = new RemoveTokenRequest();
        request.setTokenId(tokenId);
        request.setActivationId(activationId);
        return removeToken(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ExtractEncryptorResponse extractEncryptor(ExtractEncryptorRequest request) throws PowerAuthClientException {
        return extractEncryptor(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ExtractEncryptorResponse extractEncryptor(ExtractEncryptorRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/encryptor", request, queryParams, httpHeaders, ExtractEncryptorResponse.class);
    }

    @Override
    public ExtractEncryptorResponse extractEncryptor(String activationId, String applicationKey,
                                                     String nonce, String protocolVersion, Long timestamp, String temporaryKeyId) throws PowerAuthClientException {
        final ExtractEncryptorRequest request = new ExtractEncryptorRequest();
        request.setActivationId(activationId);
        request.setApplicationKey(applicationKey);
        request.setTemporaryKeyId(temporaryKeyId);
        request.setNonce(nonce);
        request.setProtocolVersion(protocolVersion);
        request.setTimestamp(timestamp);
        request.setTemporaryKeyId(temporaryKeyId);
        return extractEncryptor(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request) throws PowerAuthClientException {
        return startUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public StartUpgradeResponse startUpgrade(StartUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/upgrade/start", request, queryParams, httpHeaders, StartUpgradeResponse.class);
    }

    @Override
    public ConfirmUpgradeResponse confirmUpgrade(ConfirmUpgradeRequest request) throws PowerAuthClientException {
        return confirmUpgrade(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ConfirmUpgradeResponse confirmUpgrade(ConfirmUpgradeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/upgrade/confirm", request, queryParams, httpHeaders, ConfirmUpgradeResponse.class);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws PowerAuthClientException {
        return listActivationFlags(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/activation/flags/list", request, queryParams, httpHeaders, ListActivationFlagsResponse.class);
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
        return callV4RestApi("/activation/flags/create", request, queryParams, httpHeaders, AddActivationFlagsResponse.class);
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
        return callV4RestApi("/activation/flags/update", request, queryParams, httpHeaders, UpdateActivationFlagsResponse.class);
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
        return callV4RestApi("/activation/flags/remove", request, queryParams, httpHeaders, RemoveActivationFlagsResponse.class);
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
        return callV4RestApi("/application/roles/list", request, queryParams, httpHeaders, ListApplicationRolesResponse.class);
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
        return callV4RestApi("/application/roles/create", request, queryParams, httpHeaders, AddApplicationRolesResponse.class);
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
        return callV4RestApi("/application/roles/update", request, queryParams, httpHeaders, UpdateApplicationRolesResponse.class);
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
        return callV4RestApi("/application/roles/remove", request, queryParams, httpHeaders, RemoveApplicationRolesResponse.class);
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
        return callV4RestApi("/operation/create", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request) throws PowerAuthClientException {
        return operationDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse operationDetail(OperationDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/detail", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationDetailResponse operationClaim(OperationClaimRequest request) throws PowerAuthClientException {
        return operationClaim(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse operationClaim(OperationClaimRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/claim", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request) throws PowerAuthClientException {
        return operationList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationListResponse operationList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/list", request, queryParams, httpHeaders, OperationListResponse.class);
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request) throws PowerAuthClientException {
        return operationPendingList(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationListResponse operationPendingList(OperationListForUserRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/list/pending", request, queryParams, httpHeaders, OperationListResponse.class);
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request) throws PowerAuthClientException {
        return operationCancel(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationDetailResponse operationCancel(OperationCancelRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/cancel", request, queryParams, httpHeaders, OperationDetailResponse.class);
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request) throws PowerAuthClientException {
        return operationApprove(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse operationApprove(OperationApproveRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/approve", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request) throws PowerAuthClientException {
        return failApprovalOperation(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse failApprovalOperation(OperationFailApprovalRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/approve/fail", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request) throws PowerAuthClientException {
        return operationReject(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationUserActionResponse operationReject(OperationRejectRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/reject", request, queryParams, httpHeaders, OperationUserActionResponse.class);
    }

    @Override
    public OperationTemplateListResponse operationTemplateList() throws PowerAuthClientException {
        return callV4RestApi("/operation/template/list", null, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, OperationTemplateListResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request) throws PowerAuthClientException {
        return operationTemplateDetail(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse operationTemplateDetail(OperationTemplateDetailRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/template/detail", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws PowerAuthClientException {
        return createOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/template/create", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws PowerAuthClientException {
        return updateOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/template/update", request, queryParams, httpHeaders, OperationTemplateDetailResponse.class);
    }

    @Override
    public Response removeOperationTemplate(OperationTemplateDeleteRequest request) throws PowerAuthClientException {
        return removeOperationTemplate(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public Response removeOperationTemplate(OperationTemplateDeleteRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/operation/template/remove", request, queryParams, httpHeaders, Response.class);
    }

    @Override
    public TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request) throws PowerAuthClientException {
        return requestTelemetryReport(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    public TelemetryReportResponse requestTelemetryReport(TelemetryReportRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/telemetry/report", request, queryParams, httpHeaders, TelemetryReportResponse.class);
    }

    @Override
    public CreateApplicationConfigResponse createApplicationConfig(CreateApplicationConfigRequest request) throws PowerAuthClientException {
        return createApplicationConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public CreateApplicationConfigResponse createApplicationConfig(CreateApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/config/create", request, queryParams, httpHeaders, CreateApplicationConfigResponse.class);
    }

    @Override
    public CreateApplicationConfigResponse createApplicationConfig(String applicationId, String key, List<Object> values) throws PowerAuthClientException {
        final CreateApplicationConfigRequest request = new CreateApplicationConfigRequest();
        request.setApplicationId(applicationId);
        request.setKey(key);
        request.setValues(values);
        return createApplicationConfig(request);
    }

    @Override
    public Response removeApplicationConfig(RemoveApplicationConfigRequest request) throws PowerAuthClientException {
        return removeApplicationConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public Response removeApplicationConfig(RemoveApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/config/remove", request, queryParams, httpHeaders, Response.class);
    }

    @Override
    public Response removeApplicationConfig(String applicationId, String key) throws PowerAuthClientException {
        final RemoveApplicationConfigRequest request = new RemoveApplicationConfigRequest();
        request.setApplicationId(applicationId);
        request.setKey(key);
        return removeApplicationConfig(request);
    }

    @Override
    public GetApplicationConfigResponse getApplicationConfig(GetApplicationConfigRequest request) throws PowerAuthClientException {
        return getApplicationConfig(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public GetApplicationConfigResponse getApplicationConfig(GetApplicationConfigRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/application/config/detail", request, queryParams, httpHeaders, GetApplicationConfigResponse.class);
    }

    @Override
    public GetApplicationConfigResponse getApplicationConfig(String applicationId) throws PowerAuthClientException {
        final GetApplicationConfigRequest request = new GetApplicationConfigRequest();
        request.setApplicationId(applicationId);
        return getApplicationConfig(request);
    }

    @Override
    public TemporaryPublicKeyResponse fetchTemporaryPublicKey(TemporaryPublicKeyRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/keystore/create", request, queryParams, httpHeaders, TemporaryPublicKeyResponse.class);
    }

    @Override
    public RemoveTemporaryPublicKeyResponse removeTemporaryPublicKey(String id, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        final RemoveTemporaryPublicKeyRequest request = new RemoveTemporaryPublicKeyRequest();
        request.setId(id);
        return callV4RestApi("/keystore/remove", request, queryParams, httpHeaders, RemoveTemporaryPublicKeyResponse.class);
    }

    @Override
    public ChangePasswordResponse changePassword(ChangePasswordRequest request) throws PowerAuthClientException {
        return changePassword(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public ChangePasswordResponse changePassword(ChangePasswordRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/password/change", request, queryParams, httpHeaders, ChangePasswordResponse.class);
    }

    @Override
    public AddBiometryResponse addBiometry(AddBiometryRequest request) throws PowerAuthClientException {
        return addBiometry(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public AddBiometryResponse addBiometry(AddBiometryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/biometry/add", request, queryParams, httpHeaders, AddBiometryResponse.class);
    }

    @Override
    public Response removeBiometry(RemoveBiometryRequest request) throws PowerAuthClientException {
        return removeBiometry(request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP);
    }

    @Override
    public Response removeBiometry(RemoveBiometryRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callV4RestApi("/biometry/remove", request, queryParams, httpHeaders, Response.class);
    }

}
