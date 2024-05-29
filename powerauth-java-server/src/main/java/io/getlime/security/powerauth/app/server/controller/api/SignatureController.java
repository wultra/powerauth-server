/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AsymmetricSignatureServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.AuditingServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OfflineSignatureServiceBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OnlineSignatureServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
@RestController("signatureController")
@RequestMapping("/rest/v3/signature")
@Tag(name = "PowerAuth Signature Controller (V3)")
@Slf4j
public class SignatureController {

    private final AsymmetricSignatureServiceBehavior asymmetricSignatureService;
    private final OnlineSignatureServiceBehavior onlineSignatureService;
    private final OfflineSignatureServiceBehavior offlineSignatureService;
    private final AuditingServiceBehavior auditingService;

    @Autowired
    public SignatureController(AsymmetricSignatureServiceBehavior asymmetricSignatureService, OnlineSignatureServiceBehavior onlineSignatureService, OfflineSignatureServiceBehavior offlineSignatureService, AuditingServiceBehavior auditingService) {
        this.asymmetricSignatureService = asymmetricSignatureService;
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
    public ObjectResponse<VerifySignatureResponse> verifySignature(@RequestBody ObjectRequest<VerifySignatureRequest> request) throws Exception {
        logger.info("VerifySignatureRequest received: {}", request);
        final ObjectResponse<VerifySignatureResponse> response = new ObjectResponse<>("OK", onlineSignatureService.verifySignature(request.getRequestObject(), new ArrayList<>()));
        logger.info("VerifySignatureRequest succeeded: {}", request);
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
    public ObjectResponse<CreatePersonalizedOfflineSignaturePayloadResponse> createPersonalizedOfflineSignaturePayload(@RequestBody ObjectRequest<CreatePersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        logger.info("CreatePersonalizedOfflineSignaturePayloadRequest received: {}", request);
        final ObjectResponse<CreatePersonalizedOfflineSignaturePayloadResponse> response = new ObjectResponse<>("OK", offlineSignatureService.createPersonalizedOfflineSignaturePayload(request.getRequestObject()));
        logger.info("CreatePersonalizedOfflineSignaturePayloadRequest succeeded: {}", response);
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
    public ObjectResponse<CreateNonPersonalizedOfflineSignaturePayloadResponse> createNonPersonalizedOfflineSignaturePayload(@RequestBody ObjectRequest<CreateNonPersonalizedOfflineSignaturePayloadRequest> request) throws Exception {
        logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest received: {}", request);
        final ObjectResponse<CreateNonPersonalizedOfflineSignaturePayloadResponse> response = new ObjectResponse<>("OK", offlineSignatureService.createNonPersonalizedOfflineSignaturePayload(request.getRequestObject()));
        logger.info("CreateNonPersonalizedOfflineSignaturePayloadRequest succeeded: {}", response);
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
    public ObjectResponse<VerifyOfflineSignatureResponse> verifyOfflineSignature(@RequestBody ObjectRequest<VerifyOfflineSignatureRequest> request) throws Exception {
        logger.info("VerifyOfflineSignatureRequest received: {}", request);
        final ObjectResponse<VerifyOfflineSignatureResponse> response = new ObjectResponse<>("OK", offlineSignatureService.verifyOfflineSignature(request.getRequestObject()));
        logger.info("VerifyOfflineSignatureRequest succeeded: {}", response);
        return response;
    }

    /**
     * Validate ECDSA signature.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/ecdsa/verify")
    public ObjectResponse<VerifyECDSASignatureResponse> verifyECDSASignature(@RequestBody ObjectRequest<VerifyECDSASignatureRequest> request) throws Exception {
        logger.info("VerifyECDSASignatureRequest received: {}", request);
        final ObjectResponse<VerifyECDSASignatureResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.verifyECDSASignature(request.getRequestObject()));
        logger.info("VerifyECDSASignatureRequest succeeded: {}", response);
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
    public ObjectResponse<SignatureAuditResponse> getSignatureAuditLog(@RequestBody ObjectRequest<SignatureAuditRequest> request) throws Exception {
        logger.info("SignatureAuditRequest received: {}", request);
        final ObjectResponse<SignatureAuditResponse> response = new ObjectResponse<>("OK", auditingService.getSignatureAuditLog(request.getRequestObject()));
        logger.info("SignatureAuditRequest succeeded: {}", response);
        return response;
    }

}
