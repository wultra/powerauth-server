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

package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.OnlineSignatureServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OfflineAuthenticationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OnlineAuthenticationServiceBehavior;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateNonPersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreatePersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyOfflineAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.v3.VerifySignatureResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateNonPersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreatePersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyOfflineAuthenticationResponse;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

/**
 * Controller managing the endpoints related to authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("authenticationControllerV4")
@RequestMapping("/rest/v4/auth")
@Tag(name = "PowerAuth Authentication Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class AuthenticationController {

    private final OnlineAuthenticationServiceBehavior onlineAuthenticationService;
    private final OfflineAuthenticationServiceBehavior offlineAuthenticationService;

    private final OnlineSignatureServiceBehavior onlineSignatureService;

    /**
     * Verify authentication code.
     *
     * @param request Verify authentication code request.
     * @return Verify authentication code response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyAuthenticationResponse> verifyAuthentication(@Valid @RequestBody ObjectRequest<VerifyAuthenticationRequest> request) throws Exception {
        final VerifyAuthenticationRequest req = request.getRequestObject();
        logger.info("action: verifyAuthentication, state: initiated, activationId: {}, applicationKey: {}, authenticationVersion: {}", req.getActivationId(), req.getApplicationKey(), req.getAuthenticationVersion());
        logger.debug("action: verifyAuthentication, state: initiated, request: {}", request);

        final VerifyAuthenticationResponse response = ProtocolVersion.V40.getVersion().equals(req.getAuthenticationVersion())
                ? onlineAuthenticationService.verifyAuthentication(req, new ArrayList<>())
                : verifyAuthenticationLegacy(req);

        logger.info("action: verifyAuthentication, state: succeeded, authenticationValid: {}", response.isAuthenticationValid());
        logger.debug("action: verifyAuthentication, state: succeeded, response: {}", response);
        return new ObjectResponse<>(response);
    }

    /**
     * Create personalized offline authentication data.
     *
     * @param request Create personalized offline authentication data request.
     * @return Create personalized offline authentication data response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/personalized/create")
    public ObjectResponse<CreatePersonalizedOfflineAuthPayloadResponse> createPersonalizedOfflineAuthPayload(@Valid @RequestBody ObjectRequest<CreatePersonalizedOfflineAuthPayloadRequest> request) throws Exception {
        final CreatePersonalizedOfflineAuthPayloadRequest req = request.getRequestObject();
        logger.info("action: createPersonalizedOfflineAuthPayload, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: createPersonalizedOfflineAuthPayload, state: initiated, request: {}", request);
        final ObjectResponse<CreatePersonalizedOfflineAuthPayloadResponse> response = new ObjectResponse<>(offlineAuthenticationService.createPersonalizedOfflineAuthPayload(req));
        logger.info("action: createPersonalizedOfflineAuthPayload, state: succeeded");
        logger.debug("action: createPersonalizedOfflineAuthPayload, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Create non-personalized offline authentication data.
     *
     * @param request Create non-personalized offline authentication data request.
     * @return Create non-personalized offline authentication data response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/non-personalized/create")
    public ObjectResponse<CreateNonPersonalizedOfflineAuthPayloadResponse> createNonPersonalizedOfflineAuthPayload(@Valid @RequestBody ObjectRequest<CreateNonPersonalizedOfflineAuthPayloadRequest> request) throws Exception {
        final CreateNonPersonalizedOfflineAuthPayloadRequest req = request.getRequestObject();
        logger.info("action: createNonPersonalizedOfflineAuthPayload, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: createNonPersonalizedOfflineAuthPayload, state: initiated, request: {}", request);
        final ObjectResponse<CreateNonPersonalizedOfflineAuthPayloadResponse> response = new ObjectResponse<>(offlineAuthenticationService.createNonPersonalizedOfflineAuthPayload(req));
        logger.info("action: createNonPersonalizedOfflineAuthPayload, state: succeeded");
        logger.debug("action: createNonPersonalizedOfflineAuthPayload, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Verify offline authentication.
     *
     * @param request Verify offline authentication request.
     * @return Verify offline authentication response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/verify")
    public ObjectResponse<VerifyOfflineAuthenticationResponse> verifyOfflineAuthentication(@Valid @RequestBody ObjectRequest<VerifyOfflineAuthenticationRequest> request) throws Exception {
        final VerifyOfflineAuthenticationRequest req = request.getRequestObject();
        logger.info("action: verifyOfflineAuthentication, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifyOfflineAuthentication, state: initiated, request: {}", request);
        final ObjectResponse<VerifyOfflineAuthenticationResponse> response = new ObjectResponse<>(offlineAuthenticationService.verifyOfflineAuthentication(req));
        logger.info("action: verifyOfflineAuthentication, state: succeeded, authenticationValid: {}", response.getResponseObject().isAuthenticationValid());
        logger.debug("action: verifyOfflineAuthentication, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Verifies an authentication code using the legacy signature verification flow.
     * This method exists to support V3 signature verification when invoked through the V4
     * endpoint. It will be removed once protocol V3 support is dropped in a future release.
     *
     * @param request Verify authentication code request.
     * @return The result of the authentication verification.
     * @throws Exception In case the service throws exception.
     * @deprecated since 2.0.0, for removal once the V3 protocol is no longer supported
     */
    @Deprecated(since = "2.0.0", forRemoval = true)
    private VerifyAuthenticationResponse verifyAuthenticationLegacy(final VerifyAuthenticationRequest request) throws Exception {
        final VerifySignatureRequest legacyRequest = convert(request);
        final VerifySignatureResponse legacyResponse = onlineSignatureService.verifySignature(legacyRequest, new ArrayList<>());
        return convert(legacyResponse);
    }

    private static VerifySignatureRequest convert(final VerifyAuthenticationRequest src) {
        final VerifySignatureRequest legacyRequest = new VerifySignatureRequest();
        legacyRequest.setActivationId(src.getActivationId());
        legacyRequest.setApplicationKey(src.getApplicationKey());
        legacyRequest.setData(src.getData());
        legacyRequest.setSignature(src.getAuthenticationCode());
        legacyRequest.setSignatureVersion(src.getAuthenticationVersion());
        legacyRequest.setSignatureType(convert(src.getAuthenticationCodeType()));
        return legacyRequest;
    }

    private static VerifyAuthenticationResponse convert(final VerifySignatureResponse src) {
        final VerifyAuthenticationResponse response = new VerifyAuthenticationResponse();
        response.setAuthenticationValid(src.isSignatureValid());
        response.setActivationStatus(src.getActivationStatus());
        response.setBlockedReason(src.getBlockedReason());
        response.setActivationId(src.getActivationId());
        response.setUserId(src.getUserId());
        response.setApplicationId(src.getApplicationId());
        response.setRemainingAttempts(src.getRemainingAttempts());
        response.setApplicationRoles(src.getApplicationRoles());
        response.setActivationFlags(src.getActivationFlags());
        response.setAuthenticationCodeType(convert(src.getSignatureType()));
        return response;
    }

    private static SignatureType convert(final AuthenticationCodeType src) {
        return switch (src) {
            case POSSESSION -> SignatureType.POSSESSION;
            case KNOWLEDGE -> SignatureType.KNOWLEDGE;
            case BIOMETRY -> SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> SignatureType.POSSESSION_BIOMETRY;
            case POSSESSION_KNOWLEDGE_BIOMETRY -> SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

    private static AuthenticationCodeType convert(final SignatureType src) {
        return switch (src) {
            case POSSESSION -> AuthenticationCodeType.POSSESSION;
            case KNOWLEDGE -> AuthenticationCodeType.KNOWLEDGE;
            case BIOMETRY -> AuthenticationCodeType.BIOMETRY;
            case POSSESSION_KNOWLEDGE -> AuthenticationCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> AuthenticationCodeType.POSSESSION_BIOMETRY;
            case POSSESSION_KNOWLEDGE_BIOMETRY -> AuthenticationCodeType.POSSESSION_KNOWLEDGE_BIOMETRY;
        };
    }

}
