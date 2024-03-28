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
 *
 */
package com.wultra.security.powerauth.rest.client;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientException;
import com.wultra.security.powerauth.client.PowerAuthFido2Client;
import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorAssertionResponse;
import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorParameters;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthError;
import com.wultra.security.powerauth.client.model.request.fido2.*;
import com.wultra.security.powerauth.client.model.response.fido2.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Class implementing a PowerAuth REST client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthFido2RestClient implements PowerAuthFido2Client {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthFido2RestClient.class);

    private static final String PA_REST_FIDO2_PREFIX = "/fido2";
    private static final MultiValueMap<String, String> EMPTY_MULTI_MAP = new LinkedMultiValueMap<>();

    private final RestClient restClient;
    private final ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl BASE URL of REST endpoints.
     */
    public PowerAuthFido2RestClient(String baseUrl) throws PowerAuthClientException {
        this(baseUrl, new PowerAuthRestClientConfiguration());
    }

    /**
     * PowerAuth REST client constructor.
     *
     * @param baseUrl Base URL of REST endpoints.
     */
    public PowerAuthFido2RestClient(String baseUrl, PowerAuthRestClientConfiguration config) throws PowerAuthClientException {
        final DefaultRestClient.Builder builder = DefaultRestClient.builder().baseUrl(baseUrl)
                .acceptInvalidCertificate(config.getAcceptInvalidSslCertificate())
                .connectionTimeout(config.getConnectTimeout())
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
     * Call the PowerAuth FIDO2 API.
     *
     * @param path Path of the endpoint.
     * @param request Request object.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @param responseType Response type.
     * @return Response.
     */
    private <T> T callFido2RestApi(String path, Object request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders, Class<T> responseType) throws PowerAuthClientException {
        final ObjectRequest<?> objectRequest = new ObjectRequest<>(request);
        try {
            final ObjectResponse<T> objectResponse = restClient.postObject(PA_REST_FIDO2_PREFIX + path, objectRequest, queryParams, httpHeaders, responseType);
            return objectResponse.getResponseObject();
        } catch (RestClientException ex) {
            if (ex.getStatusCode() == null) {
                // Logging for network errors when port is closed
                logger.warn("PowerAuth FIDO2 service is not accessible, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
            } else if (ex.getStatusCode() == HttpStatus.NOT_FOUND) {
                // Logging for 404 errors
                logger.warn("PowerAuth FIDO2 service is not available, error: {}", ex.getMessage());
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
        } catch (IOException ex2) {
            // Parsing failed, return a regular error
            throw new PowerAuthClientException(ex.getMessage(), ex);
        }
    }

    @Override
    public RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(RegisteredAuthenticatorsRequest request) throws PowerAuthClientException {
        return callFido2RestApi("/registrations/list", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegisteredAuthenticatorsResponse.class);
    }

    @Override
    public RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(RegisteredAuthenticatorsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callFido2RestApi("/registrations/list", request, queryParams, httpHeaders, RegisteredAuthenticatorsResponse.class);
    }

    @Override
    public RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(String userId, String applicationId) throws PowerAuthClientException {
        final RegisteredAuthenticatorsRequest request = new RegisteredAuthenticatorsRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        return callFido2RestApi("/registrations/list", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegisteredAuthenticatorsResponse.class);
    }

    @Override
    public RegistrationChallengeResponse requestRegistrationChallenge(RegistrationChallengeRequest request) throws PowerAuthClientException {
        return callFido2RestApi("/registrations/challenge", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegistrationChallengeResponse.class);
    }

    @Override
    public RegistrationChallengeResponse requestRegistrationChallenge(RegistrationChallengeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callFido2RestApi("/registrations/challenge", request, queryParams, httpHeaders, RegistrationChallengeResponse.class);
    }

    @Override
    public RegistrationChallengeResponse requestRegistrationChallenge(String userId, String applicationId) throws PowerAuthClientException {
        final RegistrationChallengeRequest request = new RegistrationChallengeRequest();
        request.setUserId(userId);
        request.setApplicationId(applicationId);
        return callFido2RestApi("/registrations/challenge", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegistrationChallengeResponse.class);
    }

    @Override
    public RegistrationResponse register(RegistrationRequest request) throws PowerAuthClientException {
        return callFido2RestApi("/registrations", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegistrationResponse.class);
    }

    @Override
    public RegistrationResponse register(RegistrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callFido2RestApi("/registrations", request, queryParams, httpHeaders, RegistrationResponse.class);
    }

    @Override
    public RegistrationResponse register(String applicationId, String activationName, String expectedChallenge, AuthenticatorParameters authenticatorParameters) throws PowerAuthClientException {
        RegistrationRequest request = new RegistrationRequest();
        request.setApplicationId(applicationId);
        request.setActivationName(activationName);
        request.setExpectedChallenge(expectedChallenge);
        request.setAuthenticatorParameters(authenticatorParameters);
        return callFido2RestApi("/registrations", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, RegistrationResponse.class);
    }

    @Override
    public AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request) throws PowerAuthClientException {
        return callFido2RestApi("/assertions/challenge", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, AssertionChallengeResponse.class);
    }

    @Override
    public AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callFido2RestApi("/assertions/challenge", request, queryParams, httpHeaders, AssertionChallengeResponse.class);
    }

    @Override
    public AssertionChallengeResponse requestAssertionChallenge(List<String> applicationIds, String externalId, String operationType, Map<String, String> parameters) throws PowerAuthClientException {
        final AssertionChallengeRequest request = new AssertionChallengeRequest();
        return callFido2RestApi("/assertions/challenge", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, AssertionChallengeResponse.class);
    }

    @Override
    public AssertionVerificationResponse authenticate(AssertionVerificationRequest request) throws PowerAuthClientException {
        return callFido2RestApi("/assertions", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, AssertionVerificationResponse.class);
    }

    @Override
    public AssertionVerificationResponse authenticate(AssertionVerificationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException {
        return callFido2RestApi("/assertions", request, queryParams, httpHeaders, AssertionVerificationResponse.class);
    }

    @Override
    public AssertionVerificationResponse authenticate(String id, String type, String authenticatorAttachment, AuthenticatorAssertionResponse response,
                                                      String applicationId, String relyingPartyId, List<String> allowedOrigins, List<String> allowedTopOrigins,
                                                      boolean requiresUserVerification, String expectedChallenge) throws PowerAuthClientException {
        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setCredentialId(id);
        request.setType(type);
        request.setAuthenticatorAttachment(authenticatorAttachment);
        request.setResponse(response);
        request.setApplicationId(applicationId);
        request.setRelyingPartyId(relyingPartyId);
        request.setAllowedOrigins(allowedOrigins);
        request.setAllowedTopOrigins(allowedTopOrigins);
        request.setRequiresUserVerification(requiresUserVerification);
        request.setExpectedChallenge(expectedChallenge);
        return callFido2RestApi("/assertions", request, EMPTY_MULTI_MAP, EMPTY_MULTI_MAP, AssertionVerificationResponse.class);
    }

}
