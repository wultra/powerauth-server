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

import com.wultra.security.powerauth.client.model.request.v3.SignECDSARequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifyECDSASignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.SignECDSAResponse;
import com.wultra.security.powerauth.client.model.response.v3.VerifyECDSASignatureResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.AsymmetricSignatureServiceBehavior;
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
@RestController("ecdsaSignatureControllerV3")
@RequestMapping("/rest/v3/signature/ecdsa")
@Tag(name = "PowerAuth ECDSA Signature Controller (V3)")
@AllArgsConstructor
@Validated
@Slf4j
public class EcdsaSignatureController {

    private final AsymmetricSignatureServiceBehavior asymmetricSignatureService;

    /**
     * Calculate ECDSA signature.
     *
     * @param request Calculate ECDSA signature request.
     * @return Calculated ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/sign")
    public ObjectResponse<SignECDSAResponse> signDataWithECDSA(@Valid @RequestBody ObjectRequest<SignECDSARequest> request) throws Exception {
        final SignECDSARequest req = request.getRequestObject();
        logger.info("action: signDataWithECDSA, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: signDataWithECDSA, state: initiated, request: {}", request);
        final ObjectResponse<SignECDSAResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.signDataWithECDSA(req));
        logger.info("action: signDataWithECDSA, state: succeeded");
        logger.debug("action: signDataWithECDSA, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Validate ECDSA signature.
     *
     * @param request Verify ECDSA signature request.
     * @return Verify ECDSA signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyECDSASignatureResponse> verifyECDSASignature(@Valid @RequestBody ObjectRequest<VerifyECDSASignatureRequest> request) throws Exception {
        final VerifyECDSASignatureRequest req = request.getRequestObject();
        logger.info("action: verifyECDSASignature, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifyECDSASignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifyECDSASignatureResponse> response = new ObjectResponse<>("OK", asymmetricSignatureService.verifyECDSASignature(req));
        logger.info("action: verifyECDSASignature, state: succeeded, signatureValid: {}", response.getResponseObject().isSignatureValid());
        logger.debug("action: verifyECDSASignature, state: succeeded, response: {}", response);
        return response;
    }

}
