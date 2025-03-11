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

package com.wultra.security.powerauth.app.server.controller.api.v3;

import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.request.v3.CreateNonPersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.v3.CreatePersonalizedOfflineSignaturePayloadRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifyOfflineSignatureRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.OfflineSignatureServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.OnlineSignatureServiceBehavior;
import com.wultra.security.powerauth.client.model.response.v3.CreateNonPersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.v3.CreatePersonalizedOfflineSignaturePayloadResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifyOfflineSignatureResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifySignatureResponse;
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
 * Controller managing the endpoints related to authentication code and signature verification.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("signatureControllerV3")
@RequestMapping("/rest/v3/signature")
@Tag(name = "PowerAuth Signature Controller (V3)")
@Validated
@Slf4j
public class SignatureController {

    private final OnlineSignatureServiceBehavior onlineSignatureService;
    private final OfflineSignatureServiceBehavior offlineSignatureService;
    private final AuditingServiceBehavior auditingService;

    @Autowired
    public SignatureController(OnlineSignatureServiceBehavior onlineSignatureService, OfflineSignatureServiceBehavior offlineSignatureService, AuditingServiceBehavior auditingService) {
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
    public ObjectResponse<VerifySignatureResponse> verifySignature(@Valid @RequestBody ObjectRequest<VerifySignatureRequest> request) throws Exception {
        final VerifySignatureRequest req = request.getRequestObject();
        logger.info("action: verifySignature, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: verifySignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifySignatureResponse> response = new ObjectResponse<>(onlineSignatureService.verifySignature(request.getRequestObject(), new ArrayList<>()));
        logger.info("action: verifySignature, state: succeeded, signatureValid: {}", response.getResponseObject().isSignatureValid());
        logger.debug("action: verifySignature, state: succeeded, response: {}", response);
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
    public ObjectResponse<CreatePersonalizedOfflineSignaturePayloadResponse> createPersonalizedOfflineSignaturePayload(@Valid @RequestBody ObjectRequest<CreatePersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        final CreatePersonalizedOfflineSignaturePayloadRequest req = request.getRequestObject();
        logger.info("action: createPersonalizedOfflineSignaturePayload, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: createPersonalizedOfflineSignaturePayload, state: initiated, request: {}", request);
        final ObjectResponse<CreatePersonalizedOfflineSignaturePayloadResponse> response = new ObjectResponse<>(offlineSignatureService.createPersonalizedOfflineSignaturePayload(req));
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
    public ObjectResponse<CreateNonPersonalizedOfflineSignaturePayloadResponse> createNonPersonalizedOfflineSignaturePayload(@Valid @RequestBody ObjectRequest<CreateNonPersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        final CreateNonPersonalizedOfflineSignaturePayloadRequest req = request.getRequestObject();
        logger.info("action: createNonPersonalizedOfflineSignaturePayload, state: initiated, applicationId: {}", req.getApplicationId());
        logger.debug("action: createNonPersonalizedOfflineSignaturePayload, state: initiated, request: {}", request);
        final ObjectResponse<CreateNonPersonalizedOfflineSignaturePayloadResponse> response = new ObjectResponse<>(offlineSignatureService.createNonPersonalizedOfflineSignaturePayload(req));
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
    public ObjectResponse<VerifyOfflineSignatureResponse> verifyOfflineSignature(@Valid @RequestBody ObjectRequest<VerifyOfflineSignatureRequest> request) throws Exception {
        final VerifyOfflineSignatureRequest req = request.getRequestObject();
        logger.info("action: verifyOfflineSignature, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifyOfflineSignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifyOfflineSignatureResponse> response = new ObjectResponse<>(offlineSignatureService.verifyOfflineSignature(req));
        logger.info("action: verifyOfflineSignature, state: succeeded, signatureValid: {}", response.getResponseObject().isSignatureValid());
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
        final ObjectResponse<SignatureAuditResponse> response = new ObjectResponse<>(auditingService.getSignatureAuditLog(req));
        logger.info("action: getSignatureAuditLog, state: succeeded");
        logger.debug("action: getSignatureAuditLog, state: succeeded, response: {}", response);
        return response;
    }

}
