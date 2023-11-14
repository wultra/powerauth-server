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
package com.wultra.security.powerauth.client;

import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorAssertionResponse;
import com.wultra.security.powerauth.client.model.entity.fido2.AuthenticatorParameters;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.fido2.*;
import com.wultra.security.powerauth.client.model.response.fido2.*;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

/**
 * PowerAuth FIDO2 client interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PowerAuthFido2Client {

    /**
     * Get list of registered authenticators for a user.
     *
     * @param request Registered authenticator list request.
     * @return Registered authenticator list response.
     * @throws Exception In case REST API call fails.
     */
    RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(RegisteredAuthenticatorsRequest request) throws Exception;

    /**
     * Get list of registered authenticators for a user.
     *
     * @param request Registered authenticator list request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Registered authenticator list response.
     * @throws Exception In case REST API call fails.
     */
    RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(RegisteredAuthenticatorsRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws Exception;

    /**
     * Get list of registered authenticators for a user.
     *
     * @param userId User identifier.
     * @param applicationId Application identifier.
     * @return Registered authenticator list response.
     * @throws Exception In case REST API call fails.
     */
    RegisteredAuthenticatorsResponse getRegisteredAuthenticatorList(String userId, String applicationId) throws Exception;

    /**
     * Request a registration challenge.
     *
     * @param request Registration challenge request.
     * @return Registration challenge response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationChallengeResponse requestRegistrationChallenge(RegistrationChallengeRequest request) throws Exception;

    /**
     * Request a registration challenge.
     *
     * @param request Registration challenge request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Registration challenge response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationChallengeResponse requestRegistrationChallenge(RegistrationChallengeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws Exception;

    /**
     * Request a registration challenge.
     *
     * @param userId User identifier.
     * @param applicationId Application identifier.
     * @return Registration challenge response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationChallengeResponse requestRegistrationChallenge(String userId, String applicationId) throws Exception;

    /**
     * @param request Registration request.
     * @return Registration response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationResponse register(RegistrationRequest request) throws Exception;

    /**
     * @param request Registration request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Registration response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationResponse register(RegistrationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws Exception;

    /**
     * @param applicationId Application identifier.
     * @param activationName Activation name.
     * @param expectedChallenge Expected challenge.
     * @param authenticatorParameters Authenticator parameters.
     *
     * @return Registration response.
     * @throws Exception In case REST API call fails.
     */
    RegistrationResponse register(String applicationId, String activationName, String expectedChallenge, AuthenticatorParameters authenticatorParameters) throws Exception;

    /**
     * Call the assertion challenge endpoint of FIDO2 service.
     *
     * @param request Assertion challenge request.
     * @return Assertion challenge response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request) throws PowerAuthClientException;

    /**
     * Call the assertion challenge endpoint of FIDO2 service.
     *
     * @param request Assertion challenge request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Assertion challenge response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionChallengeResponse requestAssertionChallenge(AssertionChallengeRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the assertion challenge endpoint of FIDO2 service.
     *
     * @param applicationIds Application identifiers.
     * @param externalId     External identifier.
     * @param operationType  Operation type.
     * @param parameters     Parameters.
     * @return Assertion challenge response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionChallengeResponse requestAssertionChallenge(List<String> applicationIds, String externalId, String operationType, Map<String, String> parameters) throws PowerAuthClientException;

    /**
     * Call the authentication endpoint of FIDO2 service.
     *
     * @param request Assertion verification request.
     * @return Assertion verification response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionVerificationResponse authenticate(AssertionVerificationRequest request) throws PowerAuthClientException;

    /**
     * Call the authentication endpoint of FIDO2 service.
     *
     * @param request Assertion verification request.
     * @param queryParams HTTP query parameters.
     * @param httpHeaders HTTP headers.
     * @return Assertion verification response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionVerificationResponse authenticate(AssertionVerificationRequest request, MultiValueMap<String, String> queryParams, MultiValueMap<String, String> httpHeaders) throws PowerAuthClientException;

    /**
     * Call the authentication endpoint of FIDO2 service.
     *
     * @param id                       Credential identifier.
     * @param type                     Credential type.
     * @param authenticatorAttachment  Authenticator attachment.
     * @param response                 Authenticator assertion response.
     * @param applicationId            Application identifier.
     * @param relyingPartyId           Relaying party identifier.
     * @param allowedOrigins           List of allowed origins.
     * @param allowedTopOrigins        List of allowed top origins.
     * @param requiresUserVerification Whether user verification is required during authentication.
     * @param expectedChallenge        Expected challenge.
     * @return Assertion verification response.
     * @throws PowerAuthClientException In case REST API call fails.
     */
    AssertionVerificationResponse authenticate(String id, String type, String authenticatorAttachment, AuthenticatorAssertionResponse response,
                                               String applicationId, String relyingPartyId, List<String> allowedOrigins, List<String> allowedTopOrigins,
                                               boolean requiresUserVerification, String expectedChallenge) throws PowerAuthClientException;


}
