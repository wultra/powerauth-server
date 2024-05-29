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

import com.wultra.security.powerauth.client.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.client.model.response.RemoveTokenResponse;
import com.wultra.security.powerauth.client.model.response.ValidateTokenResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.TokenBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to token-based authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("tokenController")
@RequestMapping("/rest/v3/token")
@Tag(name = "PowerAuth Token Controller (V3)")
@Slf4j
public class TokenController {

    private final TokenBehavior service;

    @Autowired
    public TokenController(TokenBehavior service) {
        this.service = service;
    }

    /**
     * Create a token.
     *
     * @param request Create a new token for a simple token-based authentication.
     * @return Response with the new token information.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/create")
    public ObjectResponse<CreateTokenResponse> createToken(@RequestBody ObjectRequest<CreateTokenRequest> request) throws Exception {
        logger.info("CreateTokenRequest received: {}", request);
        final ObjectResponse<CreateTokenResponse> response = new ObjectResponse<>("OK", service.createToken(request.getRequestObject()));
        logger.info("CreateTokenRequest succeeded: {}", response);
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
    public ObjectResponse<ValidateTokenResponse> validateToken(@RequestBody ObjectRequest<ValidateTokenRequest> request) throws Exception {
        logger.info("ValidateTokenRequest received: {}", request);
        final ObjectResponse<ValidateTokenResponse> response = new ObjectResponse<>("OK", service.validateToken(request.getRequestObject()));
        logger.info("ValidateTokenRequest succeeded: {}", response);
        return response;
    }

    /**
     * Remove a token.
     *
     * @param request Remove token with given token ID.
     * @return Token removal result.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public ObjectResponse<RemoveTokenResponse> removeToken(@RequestBody ObjectRequest<RemoveTokenRequest> request) throws Exception {
        logger.info("RemoveTokenRequest received: {}", request);
        final ObjectResponse<RemoveTokenResponse> response = new ObjectResponse<>("OK", service.removeToken(request.getRequestObject()));
        logger.info("RemoveTokenRequest succeeded: {}", response);
        return response;
    }

}
