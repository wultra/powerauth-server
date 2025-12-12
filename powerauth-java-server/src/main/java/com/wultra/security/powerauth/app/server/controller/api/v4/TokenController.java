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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.TokenServiceBehavior;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.response.RemoveTokenResponse;
import com.wultra.security.powerauth.client.model.response.v4.ValidateTokenResponse;
import com.wultra.security.powerauth.client.model.response.v4.CreateTokenResponse;
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

/**
 * Controller managing the endpoints related to token-based authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("tokenControllerV4")
@RequestMapping("/rest/v4/token")
@Tag(name = "PowerAuth Token Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class TokenController {

    private final TokenServiceBehavior tokenService;

    private final com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.TokenServiceBehavior legacyTokenService;

    /**
     * Create a token.
     *
     * @param request Create a new token for a simple token-based authentication.
     * @return Response with the new token information.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateTokenResponse> createToken(@Valid @RequestBody ObjectRequest<CreateTokenRequest> request) throws Exception {
        final CreateTokenRequest req = request.getRequestObject();
        logger.info("action: createToken, state: initiated, activationId: {}, applicationKey: {}, requestTimestamp: {}", req.getActivationId(), req.getApplicationKey(), req.getTimestamp());
        logger.debug("action: createToken, state: initiated, request: {}", request);
        final ObjectResponse<CreateTokenResponse> response = new ObjectResponse<>(tokenService.createToken(req));
        logger.info("action: createToken, state: succeeded");
        logger.debug("action: createToken, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Validate a token.
     *
     * @param request Validate token during token-based authentication.
     * @return Token validation result.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/validate")
    public ObjectResponse<ValidateTokenResponse> validateToken(@Valid @RequestBody ObjectRequest<ValidateTokenRequest> request) throws Exception {
        final ValidateTokenRequest req = request.getRequestObject();
        logger.info("action: validateToken, state: initiated, tokenId: {}, requestTimestamp: {}, protocolVersion: {}", req.getTokenId(), req.getTimestamp(), req.getProtocolVersion());
        logger.debug("action: validateToken, state: initiated, request: {}", request);

        final ValidateTokenResponse response = ProtocolVersion.V40.getVersion().equals(req.getProtocolVersion())
                ? tokenService.validateToken(req)
                : validateTokenLegacy(req);

        logger.info("action: validateToken, state: succeeded, tokenValid: {}", response.isTokenValid());
        logger.debug("action: validateToken, state: succeeded, response: {}", response);
        return new ObjectResponse<>(response);
    }

    /**
     * Remove a token.
     *
     * @param request Remove token with given token ID.
     * @return Token removal result.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveTokenResponse> removeToken(@Valid @RequestBody ObjectRequest<RemoveTokenRequest> request) throws Exception {
        final RemoveTokenRequest req = request.getRequestObject();
        logger.info("action: removeToken, state: initiated, tokenId: {}", req.getTokenId());
        logger.debug("action: removeToken, state: initiated, request: {}", request);
        final ObjectResponse<RemoveTokenResponse> response = new ObjectResponse<>(tokenService.removeToken(req));
        logger.info("action: removeToken, state: succeeded");
        logger.debug("action: removeToken, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Validates token using the legacy flow.
     * This method exists to support V3 token validation when invoked through the V4
     * endpoint. It will be removed once protocol V3 support is dropped in a future release.
     *
     * @param request Validate token request.
     * @return Token validation result.
     * @throws Exception In case the service throws exception.
     * @deprecated since 2.0.0, for removal once the V3 protocol is no longer supported
     */
    @Deprecated(since = "2.0.0", forRemoval = true)
    private ValidateTokenResponse validateTokenLegacy(final ValidateTokenRequest request) throws Exception {
        return convert(legacyTokenService.validateToken(request));
    }

    private ValidateTokenResponse convert(final com.wultra.security.powerauth.client.model.response.v3.ValidateTokenResponse src) {
        final ValidateTokenResponse response = new ValidateTokenResponse();
        response.setTokenValid(src.isTokenValid());
        response.setActivationId(src.getActivationId());
        response.setActivationStatus(src.getActivationStatus());
        response.setBlockedReason(src.getBlockedReason());
        response.setUserId(src.getUserId());
        response.setApplicationId(src.getApplicationId());
        response.setAuthenticationCodeType(convert(src.getSignatureType()));
        response.setApplicationRoles(src.getApplicationRoles());
        response.setActivationFlags(src.getActivationFlags());
        return response;
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
