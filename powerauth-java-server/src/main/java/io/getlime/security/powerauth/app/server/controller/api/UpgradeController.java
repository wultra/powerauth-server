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

import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.StartUpgradeResponse;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.UpgradeServiceBehavior;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller managing the endpoints related to protocol upgrades.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("updateController")
@RequestMapping("/rest/v3/upgrade")
@Tag(name = "PowerAuth Upgrade Protocol Controller (V3)")
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
    public ObjectResponse<StartUpgradeResponse> startUpgrade(@RequestBody ObjectRequest<StartUpgradeRequest> request) throws Exception {
        logger.info("StartUpgradeRequest received: {}", request);
        final ObjectResponse<StartUpgradeResponse> response = new ObjectResponse<>("OK", service.startUpgrade(request.getRequestObject()));
        logger.info("StartUpgradeRequest succeeded: {}", response);
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
    public ObjectResponse<CommitUpgradeResponse> commitUpgrade(@RequestBody ObjectRequest<CommitUpgradeRequest> request) throws Exception {
        logger.info("CommitUpgradeRequest received: {}", request);
        final ObjectResponse<CommitUpgradeResponse> response = new ObjectResponse<>("OK", service.commitUpgrade(request.getRequestObject()));
        logger.info("CommitUpgradeRequest succeeded: {}", response);
        return response;
    }

}
