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
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.PasswordServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.ChangePasswordRequest;
import com.wultra.security.powerauth.client.model.response.v4.ChangePasswordResponse;
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
 * Controller managing the endpoints related to passwords.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("passwordControllerV4")
@RequestMapping("/rest/v4/password")
@Tag(name = "PowerAuth Password Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class PasswordController {

    private final PasswordServiceBehavior passwordServiceBehavior;

    /**
     * Change password.
     *
     * @param request Shared secret request.
     * @return Shared secret response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/change")
    public ObjectResponse<ChangePasswordResponse> changePassword(@Valid @RequestBody ObjectRequest<ChangePasswordRequest> request) throws Exception {
        final ChangePasswordRequest req = request.getRequestObject();
        logger.info("action: changePassword, state: initiated, activation ID: {}", req.getActivationId());
        logger.debug("action: changePassword, state: initiated, request: {}", request);
        final ObjectResponse<ChangePasswordResponse> response = new ObjectResponse<>(passwordServiceBehavior.changePassword(req));
        logger.info("action: changePassword, state: succeeded");
        logger.debug("action: changePassword, state: succeeded, response: {}", response);
        return response;
    }

}
