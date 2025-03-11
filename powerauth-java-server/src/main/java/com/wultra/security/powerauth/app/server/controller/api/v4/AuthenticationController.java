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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.OfflineSignatureServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.OnlineSignatureServiceBehavior;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v4.CreateNonPersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreatePersonalizedOfflineAuthPayloadRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyOfflineAuthRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.client.model.response.v4.CreateNonPersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreatePersonalizedOfflineAuthPayloadResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyOfflineAuthResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
@Validated
@Slf4j
public class AuthenticationController {

    // TODO
    private final OnlineSignatureServiceBehavior onlineSignatureService;
    private final OfflineSignatureServiceBehavior offlineSignatureService;
    private final AuditingServiceBehavior auditingService;

    @Autowired
    public AuthenticationController(OnlineSignatureServiceBehavior onlineSignatureService, OfflineSignatureServiceBehavior offlineSignatureService, AuditingServiceBehavior auditingService) {
        this.onlineSignatureService = onlineSignatureService;
        this.offlineSignatureService = offlineSignatureService;
        this.auditingService = auditingService;
    }

    /**
     * Verify signature.
     *
     * @param request Verify signature request.
     * @return Verify signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyAuthResponse> verifyAuthentication(@Valid @RequestBody ObjectRequest<VerifyAuthRequest> request) throws Exception {
        final VerifyAuthRequest req = request.getRequestObject();
        logger.info("action: verifyAuthentication, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: verifyAuthentication, state: initiated, request: {}", request);
        final ObjectResponse<VerifyAuthResponse> response = new ObjectResponse<>(onlineSignatureService.verifySignature(request.getRequestObject(), new ArrayList<>()));
        logger.info("action: verifyAuthentication, state: succeeded, authenticationValid: {}", response.getResponseObject().isAuthenticationValid());
        logger.debug("action: verifyAuthentication, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Create personalized offline signature data.
     *
     * @param request Create personalized offline signature data request.
     * @return Create personalized offline signature data response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/personalized/create")
    public ObjectResponse<CreatePersonalizedOfflineAuthPayloadResponse> createPersonalizedOfflineAuthPayload(@Valid @RequestBody ObjectRequest<CreatePersonalizedOfflineAuthPayloadRequest> request) throws Exception {
        final CreatePersonalizedOfflineAuthPayloadRequest req = request.getRequestObject();
        logger.info("action: createPersonalizedOfflineSignaturePayload, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: createPersonalizedOfflineSignaturePayload, state: initiated, request: {}", request);
        final ObjectResponse<CreatePersonalizedOfflineAuthPayloadResponse> response = new ObjectResponse<>(offlineSignatureService.createPersonalizedOfflineAuthPayload(req));
        logger.info("action: createPersonalizedOfflineSignaturePayload, state: succeeded");
        logger.debug("action: createPersonalizedOfflineSignaturePayload, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Create non-personalized offline signaure data.
     *
     * @param request Create non-personalized offline signature data request.
     * @return Create non-personalized offline signature data response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/non-personalized/create")
    public ObjectResponse<CreateNonPersonalizedOfflineAuthPayloadResponse> createNonPersonalizedOfflineAuthPayload(@Valid @RequestBody ObjectRequest<CreateNonPersonalizedOfflineAuthPayloadRequest> request) throws Exception {
        final CreateNonPersonalizedOfflineAuthPayloadRequest req = request.getRequestObject();
        logger.info("action: createNonPersonalizedOfflineSignaturePayload, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: createNonPersonalizedOfflineSignaturePayload, state: initiated, request: {}", request);
        final ObjectResponse<CreateNonPersonalizedOfflineAuthPayloadResponse> response = new ObjectResponse<>(offlineSignatureService.createNonPersonalizedOfflineAuthPayload(req));
        logger.info("action: createNonPersonalizedOfflineSignaturePayload, state: succeeded");
        logger.debug("action: createNonPersonalizedOfflineSignaturePayload, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Verify offline signature.
     *
     * @param request Verify offline signature request.
     * @return Verify offline signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/offline/verify")
    public ObjectResponse<VerifyOfflineAuthResponse> verifyOfflineAuthentication(@Valid @RequestBody ObjectRequest<VerifyOfflineAuthRequest> request) throws Exception {
        final VerifyOfflineAuthRequest req = request.getRequestObject();
        logger.info("action: verifyOfflineSignature, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifyOfflineSignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifyOfflineAuthResponse> response = new ObjectResponse<>(offlineSignatureService.verifyOfflineSignature(req));
        logger.info("action: verifyOfflineSignature, state: succeeded, signatureValid: {}", response.getResponseObject().isAuthenticationValid());
        logger.debug("action: verifyOfflineSignature, state: succeeded, response: {}", response);
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
    public ObjectResponse<SignatureAuditResponse> getSignatureAuditLog(@Valid @RequestBody ObjectRequest<SignatureAuditRequest> request) throws Exception {
        final SignatureAuditRequest req = request.getRequestObject();
        logger.info("action: getSignatureAuditLog, state: initiated, userId: {}, applicationId: {}", req.getUserId(), req.getApplicationId());
        logger.debug("action: getSignatureAuditLog, state: initiated, request: {}", request);
        // TODO - rename for v4
        final ObjectResponse<SignatureAuditResponse> response = new ObjectResponse<>(auditingService.getSignatureAuditLog(req));
        logger.info("action: getSignatureAuditLog, state: succeeded");
        logger.debug("action: getSignatureAuditLog, state: succeeded, response: {}", response);
        return response;
    }

}
