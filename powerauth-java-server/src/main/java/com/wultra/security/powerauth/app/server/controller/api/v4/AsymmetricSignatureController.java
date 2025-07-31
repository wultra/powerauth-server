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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.AsymmetricSignatureServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.SignAsymmetricRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAsymmetricSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignAsymmetricResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAsymmetricSignatureResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("dsaControllerV4")
@RequestMapping("/rest/v4/dsa")
@Tag(name = "DSA Signature Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class AsymmetricSignatureController {

    private final AsymmetricSignatureServiceBehavior asymmetricSignatureService;

    /**
     * Calculate asymmetric signature.
     *
     * @param request Calculate asymmetric signature request.
     * @return Calculated asymmetric signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/sign")
    public ObjectResponse<SignAsymmetricResponse> signData(@Valid @RequestBody ObjectRequest<SignAsymmetricRequest> request) throws Exception {
        final SignAsymmetricRequest req = request.getRequestObject();
        logger.info("action: signData, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: signData, state: initiated, request: {}", request);
        final ObjectResponse<SignAsymmetricResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.signData(req));
        logger.info("action: signData, state: succeeded");
        logger.debug("action: signData, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Validate asymmetric signature.
     *
     * @param request Verify asymmetric signature request.
     * @return Verify asymmetric signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyAsymmetricSignatureResponse> verifySignature(@Valid @RequestBody ObjectRequest<VerifyAsymmetricSignatureRequest> request) throws Exception {
        final VerifyAsymmetricSignatureRequest req = request.getRequestObject();
        logger.info("action: verifySignature, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifySignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifyAsymmetricSignatureResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.verifySignature(req));
        logger.info("action: verifySignature, state: succeeded, signatureValid: {}", response.getResponseObject().isSignatureValid());
        logger.debug("action: verifySignature, state: succeeded, response: {}", response);
        return response;
    }

}
