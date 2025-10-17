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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.JwtSignatureServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.SignJwtRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyJwtSignatureRequest;
import com.wultra.security.powerauth.client.model.response.v4.SignJwtResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyJwtSignatureResponse;
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
 * JWT signature controller.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("jwtControllerV4")
@RequestMapping("/rest/v4/jwt")
@Tag(name = "JWT Signature Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class JwtSignatureController {

    private final JwtSignatureServiceBehavior jwtSignatureServiceBehavior;

    /**
     * Sign a JWT.
     *
     * @param request Sign JWT request.
     * @return Sign JWT response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/sign")
    public ObjectResponse<SignJwtResponse> signJwt(@Valid @RequestBody ObjectRequest<SignJwtRequest> request) throws Exception {
        final SignJwtRequest req = request.getRequestObject();
        logger.info("action: signJwt, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: signJwt, state: initiated, request: {}", request);
        final ObjectResponse<SignJwtResponse> response = new ObjectResponse<>("OK", jwtSignatureServiceBehavior.signJwt(req));
        logger.info("action: signJwt, state: succeeded");
        logger.debug("action: signJwt, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Verify a JWT signature.
     *
     * @param request Verify JWT signature request.
     * @return Verify JWT signature response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/verify")
    public ObjectResponse<VerifyJwtSignatureResponse> verifyJwtSignature(@Valid @RequestBody ObjectRequest<VerifyJwtSignatureRequest> request) throws Exception {
        final VerifyJwtSignatureRequest req = request.getRequestObject();
        logger.info("action: verifyJwtSignature, state: initiated, activationId: {}", req.getActivationId());
        logger.debug("action: verifyJwtSignature, state: initiated, request: {}", request);
        final ObjectResponse<VerifyJwtSignatureResponse> response = new ObjectResponse<>("OK", jwtSignatureServiceBehavior.verifyJwtSignature(req));
        logger.info("action: verifyJwtSignature, state: succeeded, signatureValid: {}", response.getResponseObject().isSignatureValid());
        logger.debug("action: verifyJwtSignature, state: succeeded, response: {}", response);
        return response;
    }

}
