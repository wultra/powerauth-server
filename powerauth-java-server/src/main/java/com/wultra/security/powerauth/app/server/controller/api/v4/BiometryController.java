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
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.BiometryServiceBehavior;
import com.wultra.security.powerauth.client.model.request.v4.AddBiometryRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveBiometryRequest;
import com.wultra.security.powerauth.client.model.response.v4.AddBiometryResponse;
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
 * Controller managing the endpoints related to biometry setup.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("biometryControllerV4")
@RequestMapping("/rest/v4/biometry")
@Tag(name = "PowerAuth Biometry Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class BiometryController {

    private final BiometryServiceBehavior biometryServiceBehavior;

    /**
     * Set up biometry.
     *
     * @param request Add biometry request.
     * @return Add biometry response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/add")
    public ObjectResponse<AddBiometryResponse> addBiometry(@Valid @RequestBody ObjectRequest<AddBiometryRequest> request) throws Exception {
        final AddBiometryRequest req = request.getRequestObject();
        logger.info("action: addBiometry, state: initiated, activation ID: {}", req.getActivationId());
        logger.debug("action: addBiometry, state: initiated, request: {}", request);
        final ObjectResponse<AddBiometryResponse> response = new ObjectResponse<>(biometryServiceBehavior.addBiometry(req));
        logger.info("action: addBiometry, state: succeeded");
        logger.debug("action: addBiometry, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Remove biometry.
     *
     * @param request Remove biometry request.
     * @return Response
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/remove")
    public Response removeBiometry(@Valid @RequestBody ObjectRequest<RemoveBiometryRequest> request) throws Exception {
        final RemoveBiometryRequest req = request.getRequestObject();
        logger.info("action: removeBiometry, state: initiated, activation ID: {}", req.getActivationId());
        logger.debug("action: removeBiometry, state: initiated, request: {}", request);
        biometryServiceBehavior.removeBiometry(req);
        logger.info("action: removeBiometry, state: succeeded");
        logger.debug("action: removeBiometry, state: succeeded, response: empty");
        return new Response();
    }
}
