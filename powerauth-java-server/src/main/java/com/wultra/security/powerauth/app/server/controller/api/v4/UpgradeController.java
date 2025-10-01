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

import com.wultra.security.powerauth.client.model.request.v4.ConfirmUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.v4.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.v4.ConfirmUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.v4.StartUpgradeResponse;
import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.UpgradeServiceBehavior;
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
 * Controller managing the endpoints related to protocol upgrades.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("updateControllerV4")
@RequestMapping( "/rest/v4/upgrade")
@Tag(name = "PowerAuth Upgrade Protocol Controller (V4)")
@AllArgsConstructor
@Validated
@Slf4j
public class UpgradeController {

    private final UpgradeServiceBehavior service;

    /**
     * Start upgrade process.
     *
     * @param request Start upgrade request.
     * @return Start upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/start")
    public ObjectResponse<StartUpgradeResponse> startUpgrade(@Valid @RequestBody ObjectRequest<StartUpgradeRequest> request) throws Exception {
        final StartUpgradeRequest req = request.getRequestObject();
        logger.info("action: startUpgrade, state: initiated, activationId: {}, applicationKey: {}, requestTimestamp: {}", req.getActivationId(), req.getApplicationKey(), req.getTimestamp());
        logger.debug("action: startUpgrade, state: initiated, request: {}", request);
        final ObjectResponse<StartUpgradeResponse> response = new ObjectResponse<>(service.startUpgrade(req));
        logger.info("action: startUpgrade, state: succeeded");
        logger.debug("action: startUpgrade, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Confirm the upgrade.
     *
     * @param request Confirm upgrade request.
     * @return Confirm upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/confirm")
    public ObjectResponse<ConfirmUpgradeResponse> confirmUpgrade(@Valid @RequestBody ObjectRequest<ConfirmUpgradeRequest> request) throws Exception {
        final ConfirmUpgradeRequest req = request.getRequestObject();
        logger.info("action: confirmUpgrade, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: confirmUpgrade, state: initiated, request: {}", request);
        final ObjectResponse<ConfirmUpgradeResponse> response = new ObjectResponse<>(service.confirmUpgrade(req));
        logger.info("action: confirmUpgrade, state: succeeded");
        logger.debug("action: confirmUpgrade, state: succeeded, response: {}", response);
        return response;
    }

}
