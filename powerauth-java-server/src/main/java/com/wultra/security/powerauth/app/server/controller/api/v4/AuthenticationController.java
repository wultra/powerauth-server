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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.AuditingServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OfflineAuthenticationServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OnlineAuthenticationServiceBehavior;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.CreateNonPersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreatePersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyOfflineAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.CreateNonPersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreatePersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyOfflineAuthenticationResponse;
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
    private final AuditingServiceBehavior auditingService;

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
        logger.info("action: verifyAuthentication, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: verifyAuthentication, state: initiated, request: {}", request);
        final ObjectResponse<VerifyAuthenticationResponse> response = new ObjectResponse<>(onlineAuthenticationService.verifyAuthentication(request.getRequestObject(), new ArrayList<>()));
        logger.info("action: verifyAuthentication, state: succeeded, authenticationValid: {}", response.getResponseObject().isAuthenticationValid());
        logger.debug("action: verifyAuthentication, state: succeeded, response: {}", response);
        return response;
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
     * Get the audit of signatures.
     *
     * @param request Signature audit request.
     * @return Signature audit response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/list")
    public ObjectResponse<SignatureAuditResponse> getAuthenticationAuditLog(@Valid @RequestBody ObjectRequest<SignatureAuditRequest> request) throws Exception {
        final SignatureAuditRequest req = request.getRequestObject();
        logger.info("action: getSignatureAuditLog, state: initiated, userId: {}, applicationId: {}", req.getUserId(), req.getApplicationId());
        logger.debug("action: getSignatureAuditLog, state: initiated, request: {}", request);
        final ObjectResponse<SignatureAuditResponse> response = new ObjectResponse<>(auditingService.getAuthenticationLog(req));
        logger.info("action: getSignatureAuditLog, state: succeeded");
        logger.debug("action: getSignatureAuditLog, state: succeeded, response: {}", response);
        return response;
    }

}
