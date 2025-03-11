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

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.UpgradeServiceBehavior;
import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.v3.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.v3.StartUpgradeResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to protocol upgrades (V3).
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("updateControllerV3")
@RequestMapping("/rest/v3/upgrade")
@Tag(name = "PowerAuth Upgrade Protocol Controller (V3)")
@Validated
@Slf4j
public class UpgradeController {

    private final UpgradeServiceBehavior service;

    @Autowired
    public UpgradeController(UpgradeServiceBehavior service) {
        this.service = service;
    }

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
        logger.info("action: startUpgrade, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: startUpgrade, state: initiated, request: {}", request);
        final ObjectResponse<StartUpgradeResponse> response = new ObjectResponse<>(service.startUpgrade(req));
        logger.info("action: startUpgrade, state: succeeded");
        logger.debug("action: startUpgrade, state: succeeded, response: {}", response);
        return response;
    }

    /**
     * Commit the upgrade process.
     *
     * @param request Commit upgrade request.
     * @return Commit upgrade response.
     * @throws Exception In case the service throws exception.
     */
    @PostMapping("/commit")
    public ObjectResponse<CommitUpgradeResponse> commitUpgrade(@Valid @RequestBody ObjectRequest<CommitUpgradeRequest> request) throws Exception {
        final CommitUpgradeRequest req = request.getRequestObject();
        logger.info("action: commitUpgrade, state: initiated, activationId: {}, applicationKey: {}", req.getActivationId(), req.getApplicationKey());
        logger.debug("action: commitUpgrade, state: initiated, request: {}", request);
        final ObjectResponse<CommitUpgradeResponse> response = new ObjectResponse<>(service.commitUpgrade(req));
        logger.info("action: commitUpgrade, state: succeeded");
        logger.debug("action: commitUpgrade, state: succeeded, response: {}", response);
        return response;
    }

}
